"""A card is the manager's last step (the owner, 17 November 2026: "Creating a card has to be the final resource, not
one more tool to be used easily", then "Yes, build it"). Each item names its reason, and the hub refuses what it can
see is not the owner's to do: fleet work through the owner's Mac, access that an agent holds or that the manager can
grant, a decision that no words of the owner keep for them, and a sign-in to a website, which an agent makes with the
vault's login. An in-process hub with the owner API's harness; no fleet, no network and no AI call."""
import unittest
import uuid
from unittest.mock import patch

import hub
from test_ui_api import OwnerAPI

BLOCK = "```\ngh workflow run release.yml -R acme/web\n```"


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    suite.addTests(Reasons(name) for name in Reasons.__dict__ if name.startswith("test_"))
    return suite


class Reasons(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["dev"] = {"role": "worker", "runtime": "claude", "machine": "worker-1", "can": [],
                                     "repos": {"acme/web": "write"}}
        hub.TEAM["agents"]["ivy"] = {"role": "worker", "runtime": "claude", "machine": "studio-1", "can": []}
        # the owner's own words come from the hub's records here, and never from the files of this checkout
        for name, value in (("kit_revision", lambda fresh=False: None), ("knowledge_entries", lambda: [])):
            patcher = patch.object(hub, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def card(self, **fields):
        """The manager's tool with a plain choice that `fields` change: the new item's id, or the refusal's words."""
        said, error = hub.call_tool("manager", "raise_needs_you", dict(
            {"title": "Pick the release day", "why": "Two days fit.", "what_to_do": "Press one",
             "options": ["Monday", "Friday"]}, **fields))
        return said if error else int(said.split("N-")[1].split(".")[0])

    def refused(self, words, **fields):
        before = self.count("needs")
        said = self.card(**fields)
        self.assertIsInstance(said, str, fields)
        self.assertIn(words, said)
        self.assertEqual(self.count("needs"), before)
        return said

    def owner_said(self, words, author_kind="owner"):
        hub.q("INSERT INTO standing(agent,scope,kind,words,author_kind,author,created) VALUES('manager','team',"
              "'instruction',?,?,?,?)", (words, author_kind, "owner" if author_kind == "owner" else "manager",
                                         hub.now()))

    def test_an_item_with_no_reason_rings_nothing_and_the_hubs_own_kinds_need_none(self):
        said = self.refused("give the item its reason")
        for reason in hub.CARD_REASONS:
            self.assertIn(reason, said)
        self.refused("give the item its reason", reason="urgent")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='owner' AND kind='notify'")["n"], 0)
        phone = dict(title="Scan the Add device picture", add_device=True, options=["Show the picture", "Not now"],
                     what_to_do="Press **Show the picture** in Founderizer on your Mac, and scan it with your iPhone so "
                                "that push notifications reach it.")
        self.assertIsInstance(self.card(**phone), int)
        # a kind of the hub's own takes no reason, but no command either
        self.refused("gives fleet work", **dict(phone, what_to_do=f"On your Mac, run:\n\n{BLOCK}"))

    def test_fleet_work_through_the_owners_mac_is_refused(self):
        """The shapes of the cards that the owner refused on 17 November 2026, and the next ones that a manager would
        try: a command to run (in a block, in a line, under Details, with Run), a workflow's own button, a session or
        fleet work on their Mac, and an option in their voice that runs, releases or pushes."""
        for fields in ({"run_command": "gh workflow run release.yml -R acme/web", "run_on": "mac"},
                       {"what_to_do": f"On your Mac, run:\n\n{BLOCK}"},
                       {"what_to_do": "On your Mac, run `gh workflow run release.yml -R acme/web`, then press Done."},
                       {"what_to_do": "Type `gh auth login` on your Mac, then press Done."},
                       {"what_to_do": "Do the steps under Details.", "details": BLOCK},
                       {"what_to_do": "Open Terminal on your Mac and paste the command under Details.", "details": BLOCK},
                       {"what_to_do": "Paste the steps under Details in a terminal."},
                       {"what_to_do": "Open the release page and press **Run workflow**."},
                       {"what_to_do": "SSH into worker-7 and restart the hub service."},
                       {"what_to_do": "Run gh workflow run release.yml -R acme/web on studio-1."},
                       {"what_to_do": "Open a Claude Code session on your Mac and paste the steps under Details."},
                       {"what_to_do": "Ask Claude Code on your Mac to release acme/web."},
                       {"what_to_do": "On your Mac, open Claude Code and log the result in the sheet."},
                       {"title": "Have your Claude Code session move the agent"},
                       {"title": "Release acme/web from your Mac"},
                       {"options": ["Yes: my Mac session releases it", "No"]},
                       {"options": ["Yes: the developer writes it, I release it", "No"]},
                       {"options": ["I ran the restart", "Not now"]},
                       {"options": ["Yes, I'll ship it tonight", "No"]},
                       {"options": ["Yes, I'll deploy", "No"]},
                       {"options": ["I'll merge the PR", "No"]},
                       {"options": ["I'll redeploy it from my MacBook", "No"]}):
            with self.subTest(fields=fields):
                said = self.refused("gives fleet work to the owner's Mac or to the owner", reason="money", **fields)
                self.assertIn("raise an item with reason access", said)

    def test_what_only_the_owner_can_do_reaches_them(self):
        """New money, access that the fleet does not hold, the owner's own sign-in to an AI provider, their phone, and
        a hand at a machine: these cards stay, also when their words name a terminal, a session or a sign-in."""
        person = dict(reason="person", options=["Done", "Not now"])
        for fields in (dict(reason="money", title="Pay for a second server?", why="It costs 9 EUR a month."),
                       dict(reason="money", options=["No, I'd push it to next month", "No, I'll publish nothing"]),
                       dict(reason="access", needs_access="a deploy role in the cloud account"),
                       dict(reason="access", needs_access="the shop's API key",
                            what_to_do="Paste the shop's key into Fleet Vault on your Mac."),
                       dict(person, title="Sign Claude's Chrome extension in on studio-1",
                            why="Your Claude session was signed out on worker-1 at 09:10.",
                            what_to_do="1. On studio-1, open Chrome.\n2. In the Claude panel, click **Sign in**."),
                       dict(person, title="Sign in at https://claude.ai on studio-1"),
                       dict(person, title="Open Claude.app on studio-1 and sign in with your Claude account"),
                       dict(person, title="Sign in to Notion again",
                            what_to_do="In Founderizer on your Mac: Settings, Apps, MCP servers, Sign in again on its row."),
                       dict(person, title="Sign in to the App Store on studio-1 with your Apple ID"),
                       dict(person, title="Approve the sign-in to Google on your phone"),
                       dict(reason="person", title="Which server takes the designer?", options=["worker-8", "worker-9"]),
                       dict(person, title="Allow JavaScript from Apple Events on studio-1",
                            why="The designer works in a Mac session on studio-1.",
                            what_to_do="At studio-1's own keyboard, in Chrome, choose View > Developer > Allow "
                                       "JavaScript from Apple Events, then click OK on the prompt in Terminal."),
                       dict(person, title="Allow Terminal on your Mac",
                            what_to_do="On your Mac, open System Settings, Privacy, Full Disk Access, and switch on "
                                       "Terminal."),
                       dict(person, title="Allow Full Disk Access on studio-1",
                            what_to_do="At studio-1's own keyboard, open System Settings > Privacy & Security > Full "
                                       "Disk Access, switch on Terminal, and enter the Mac's password."),
                       dict(person, title="Switch studio-1 on",
                            what_to_do="Press the power button of studio-1, then log in to it at its keyboard.",
                            options=["Done: I restarted it", "Not now"]),
                       dict(person, title="Approve the agent's sign-in", what_to_do="Approve it on your phone."),
                       # the hub's own notice of a signed-out agent asks for this one
                       dict(person, title="Sign Customer Support in again", why="Its Claude session was signed out.",
                            what_to_do="Open Customer Support in Founderizer on your Mac and sign it in to Claude "
                                       "Code."),
                       # a word or a code that a page or a prompt asks for is no command
                       dict(person, title="Confirm the cancellation",
                            what_to_do="On the Apple ID page on your phone, type `CANCEL` in the box, then enter the "
                                       "code `482 913` and press **Confirm**."),
                       # an email address is an account's name, not a website
                       dict(person, title="Approve the sign-in for sales@acme.com on your phone"),
                       dict(person, title="Link WhatsApp again", why="The account of support@acme.com was logged out.",
                            what_to_do="Scan the picture in Founderizer with your phone."),
                       dict(person, title="Approve the agent's sign-in to ahrefs.com on your phone")):
            with self.subTest(fields=fields):
                self.assertIsInstance(self.card(**fields), int)

    def test_a_website_sign_in_is_the_agents_work(self):
        for fields in (dict(title="Sign in to Ahrefs on studio-1"), dict(title="Log into Ahrefs on studio-1"),
                       dict(title="Sign back in to Ahrefs on studio-1"),
                       dict(title="Sign in to webstudio-1tools on studio-1"),     # a fleet name inside a site's name
                       dict(title="Sign in to the analytics site", why="The Codex agent needs it."),
                       dict(title="Sign in to sales@acme.com on studio-1"),       # an account, of a site
                       dict(title="Log in to dashboard.acme.com as sales@acme.com"),
                       # the owner's phone in the next sentence makes no sign-in before it theirs
                       dict(what_to_do="Sign in to https://shop.example.com with your password. Then approve the code "
                                       "on your phone."),
                       dict(what_to_do="Sign in to ahrefs.com as sales@acme.com. Approve it on your phone."),
                       dict(what_to_do="Sign in to https://dashboard.stripe.com in Chrome on studio-1, then press "
                                       "Done in Founderizer.")):
            with self.subTest(fields=fields):
                self.assertIn("request_secret", self.refused("a sign-in to a website is the agent's work",
                                                             reason="person", options=["Done", "Not now"], **fields))

    def test_access_that_an_agent_holds_or_the_manager_can_grant_never_reaches_the_owner(self):
        said = self.refused("dev (write) holds the GitHub repository acme/web", reason="access",
                            needs_access="repo:acme/web")
        self.assertIn("create_task", said)
        self.assertIsInstance(self.card(reason="access", needs_access="repo:acme/web", needs_level="deploy"), int)
        hub.TEAM["agents"]["dev"]["repos"] = {"Acme/Web": "write"}            # a name in another case is the same
        self.refused("holds the GitHub repository", reason="access", needs_access="repo:acme/web")
        self.refused("not one thing that the fleet's record names", reason="access",
                     needs_access="repo:acme/web for dev")
        self.refused("Give it as repo:acme/web", reason="access", needs_access="write access to acme/web.")
        hub.TEAM["agents"]["ivy"]["google"] = {"gmail": {"account": "sales@acme.com", "level": "read"}}
        self.refused("Give it as gmail:sales@acme.com", reason="access", needs_access="the sales@acme.com mailbox")
        hub.TEAM["resources"] = {"repo:acme/docs": {"max": "write"}}
        self.assertIn('grant_access(agent="<the agent that needs it>"', self.refused(
            "is yours to give", reason="access", needs_access="repo:acme/docs"))
        self.refused("names the thing in needs_access", reason="access")
        # the hub's own words send no manager to a card that this check refuses: a repository that an agent holds
        # goes to that agent, and one that no agent holds goes to the owner
        said, error = hub.call_tool("manager", "grant_access", {"agent": "ivy", "resource": "repo:acme/web",
                                                                "level": "write"})
        self.assertTrue(error)
        self.assertIn("dev holds it: give that part of the work to dev", said)
        self.assertNotIn("raise_needs_you", said)
        # a key's value is what the hub never sees: a revoked one is the owner's to replace
        key = "bws://00000000-0000-4000-8000-00000000c0de"
        hub.TEAM["logins"] = {key: {"kind": "api_key", "env": "SHOP_KEY", "title": "Shop API"}}
        hub.TEAM["agents"]["dev"]["secrets"] = {key: "use"}
        self.assertIn('needs_level "value"', self.refused("dev (use) holds", reason="access",
                                                          needs_access=f"secret:{key}"))
        self.assertIsInstance(self.card(reason="access", needs_access=f"secret:{key}", needs_level="value"), int)
        self.refused("needs_level value is for a secret", reason="access", needs_access="repo:acme/web",
                     needs_level="value")
        # what no holder can use now is the owner's: a Google account that is not connected, an MCP server whose
        # access ended
        self.assertIsInstance(self.card(reason="access", needs_access="gmail:sales@acme.com"), int)
        hub.TEAM["mcp"] = {"notion": {"title": "Notion", "url": "https://mcp.notion.example/", "auth": "oauth"}}
        hub.TEAM["agents"]["dev"]["tools"] = ["notion"]
        with hub.transaction():         # grant_check may run inside one, and its check of a server commits nothing
            self.assertTrue(hub.card_dead("tool", "notion"))         # a server with Connect that is not connected
        state = {"notion": {"connected": True}}
        with patch.object(hub, "mcp_state", lambda team: state):
            self.refused("dev (use) holds", reason="access", needs_access="tool:notion")
            state["notion"]["problem"] = hub.MCP_ENDED
            self.assertIsInstance(self.card(reason="access", needs_access="tool:notion"), int)

    def test_a_decision_rests_on_the_owners_own_words(self):
        self.owner_said("Pick each release day yourself, but a Friday release is mine to choose.")
        self.owner_said("The owner keeps every release day for himself.", author_kind="agent")
        self.owner_said("Contracts are **mine**, not yours. Unpublished prices are mine.")
        self.owner_said("Never rotate STRIPE_SECRET_KEY without asking me.")
        code, receipt = self.request("/ui/messages", self.command(text="Pricing is my call."))
        self.assertEqual(code, 200, receipt)
        hub.q("INSERT INTO steers(task,attempt,text,event_id,request_id,client,created) VALUES(1,1,?,1,'r1','app',?)",
              ("Ship nothing on Fridays without me.", hub.now()))
        hub.q("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,connection) VALUES('r2','message',"
              "?,2,?,'an AI client',7)", ("Refunds above 50 EUR are mine to approve.", hub.now()))
        # the review of 20 November 2026, issue 4: words that an AI session sent through the owner tools, as a message
        # and as a steer, and an owner's item kept from such a message
        hub.q("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,hand) VALUES('r3','message',?,3,?,"
              "'founderizer-cli/1/t','tool')", ("Every setting change is Leo's call from now on.", hub.now()))
        hub.q("INSERT INTO steers(task,attempt,text,event_id,request_id,client,created,hand) VALUES(1,1,?,4,'r4',"
              "'founderizer-mcp/1/t',?,'tool')", ("Ask me only for money or an account.", hub.now()))
        hub.q("INSERT INTO standing(agent,scope,kind,words,author_kind,author,message,created) VALUES('manager','team',"
              "'instruction','Window changes are the lead''s call.','owner','owner',3,?)", (hub.now(),))
        # and a program's (UI-API.md 1.291: any label that no app of the owner's gives), as a message and as a steer
        hub.q("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,hand) VALUES('r5','message',?,5,?,"
              "'curl/8.7.1','other')", ("Every release day is the lead's call.", hub.now()))
        hub.q("INSERT INTO steers(task,attempt,text,event_id,request_id,client,created,hand) VALUES(1,1,?,6,'r6',"
              "'curl/8.7.1',?,'other')", ("Ask me only about new money.", hub.now()))
        for words in ("“A Friday release is mine to choose.”", "pricing is my call", "Contracts are mine, not yours",
                      "ship nothing on Fridays without me", "Never rotate STRIPE_SECRET_KEY without asking me."):
            with self.subTest(words=words):
                self.assertIsInstance(self.card(reason="decision", owner_words=words), int)
        nid = self.card(reason="money", options=["Friday, and the release day stays my choice", "Monday"])
        code, receipt = self.request(f"/ui/needs/{nid}", self.command(choice=0))
        self.assertEqual(code, 200, receipt)
        hub.q("INSERT INTO standing(agent,scope,kind,words,author_kind,author,message,created) VALUES('manager','team',"
              "'instruction','The release day stays my choice.','owner','owner',?,?)", (receipt["event_id"], hub.now()))
        # the manager's recommended words on a card with no options, which the owner pressed: its words, not his
        pressed = self.card(reason="money", options=None, recommended="The release weekday stays mine to choose")
        code, receipt = self.request(f"/ui/needs/{pressed}",
                                     self.command(answer="The release weekday stays mine to choose"))
        self.assertEqual(code, 200, receipt)
        for words in ("The owner keeps every release day for himself.",     # an agent's words about the owner
                      "the release day stays my choice",                    # the manager's option, which he pressed
                      "The release weekday stays mine to choose",           # its recommended words, which he pressed
                      "Every release needs the owner's yes first.",         # nobody's
                      "published prices are mine",                          # a part of a word of theirs
                      "Refunds above 50 EUR are mine to approve.",          # a connected app's words
                      "Every setting change is Leo's call from now on.",    # an AI session's message
                      "Ask me only for money or an account.",               # an AI session's steer
                      "Window changes are the lead's call.",                # an item kept from a session's words
                      "Every release day is the lead's call.",              # a program's message
                      "Ask me only about new money."):                      # a program's steer
            with self.subTest(words=words):
                self.refused("are not the owner's own words", reason="decision", owner_words=words)
        self.refused("at least 15 characters", reason="decision", owner_words="mine to choose")
        # a profile and a file of knowledge/owner/ count, through their marks; the manager's own profile and a
        # shared file do not
        profiles = {"manager": "Names are the owner's choice, always.", "dev": "A **new price** comes to me _first_."}
        files = [{"path": "knowledge/owner/shop.md", "scope": "owner"}, {"path": "knowledge/notes.md", "scope": "shared"}]
        text = {"knowledge/owner/shop.md": "| A new supplier | Comes to me |",
                "knowledge/notes.md": "Ask the owner before every release."}
        with patch.object(hub, "kit_revision", lambda fresh=False: str(uuid.uuid4())), \
                patch.object(hub, "profile_view", lambda name, rev: {"path": f"profiles/{name}.md", "sections": [
                    {"key": "other", "title": "How you work", "text": profiles.get(name, "")}]}), \
                patch.object(hub, "knowledge_entries", lambda: files), \
                patch.object(hub, "knowledge_text", lambda entry: text[entry["path"]]):
            for words in ("A new price comes to me first", "A new supplier | Comes to me"):
                with self.subTest(words=words):
                    self.assertIsInstance(self.card(reason="decision", owner_words=words), int)
            for words in ("Names are the owner's choice, always.", "Ask the owner before every release."):
                with self.subTest(words=words):
                    self.refused("are not the owner's own words", reason="decision", owner_words=words)
        # files that cannot be read now hold words that nobody can check, never words that are not the owner's, and
        # a file whose text cannot be read leaves no empty text in the cache for the next card
        unread = "Not raised: the knowledge files cannot be read now, so the hub cannot check owner_words in them."
        with patch.object(hub, "kit_revision", lambda fresh=False: str(uuid.uuid4())), \
                patch.object(hub, "knowledge_entries", lambda: hub.UnreadCatalog()):
            self.refused(unread, reason="decision", owner_words="A new supplier | Comes to me")
        rev = str(uuid.uuid4())
        with patch.object(hub, "kit_revision", lambda fresh=False: rev), \
                patch.object(hub, "profile_view", lambda name, rev: {"path": f"profiles/{name}.md", "sections": []}), \
                patch.object(hub, "knowledge_entries", lambda: files):
            with patch.object(hub, "knowledge_text", lambda entry: None):
                self.refused(unread, reason="decision", owner_words="A new supplier | Comes to me")
            with patch.object(hub, "knowledge_text", lambda entry: text[entry["path"]]):
                self.assertIsInstance(self.card(reason="decision", owner_words="A new supplier | Comes to me"), int)


if __name__ == "__main__":
    unittest.main()

"""A card is the manager's last step (the owner, 17 November 2026: "Creating a card has to be the final resource, not
one more tool to be used easily", then "Yes, build it"). Each item names its reason, and the hub refuses what it can
see is not the owner's to do: fleet work through the owner's Mac, access that an agent holds or that the manager can
grant, a decision that no words of the owner keep for them, and a sign-in to a website, which an agent makes with the
vault's login. An in-process hub with the owner API's harness; no fleet, no network and no AI call."""
import json
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

    def test_a_value_reaches_only_the_secure_form_and_never_a_cards_steps_or_its_answer(self):
        """A card asks the owner for no value of a key or a login: not with steps into the vault, under any reason and
        in its details too (the owner's picture of 21 November 2026, "open the vault entry ... and replace its value",
        and the same in other words or in Spanish), and not as the item's answer in words, which is in the records
        before anything masks it, whatever app the card names. The steps get the route of the new value,
        request_secret's secure form. A bug that checks only needs_level, one reason, or no details, that finds a login
        only by its whole title, that forgets the place of an earlier step ("1. Open the vault entry X. 2. Replace its
        value"), that takes the word "vault" for the vault ("so that its vault can start"), a grant on the Secrets page
        for a new value ("set X to Uses it for Ada"), or "key" as an adjective for a key ("Tell me the key date"), or
        that misses "type ... as your answer" or "reply with the key", either raises such a card or refuses the owner's
        own honest steps, which pass here. The cases are the scope written above card_value_steps and ASKS_IN_ANSWER:
        the owner's card with paste or enter, a value after a soft verb's "with", a password two steps after a vault
        only when that vault named a login, and an ask that ends at "here", "now" or "in your reply"."""
        door = "bws://00000000-0000-4000-8000-00000000b2de"
        login = "bws://00000000-0000-4000-8000-00000000d0de"
        hub.TEAM["agents"]["ada"] = {"role": "worker", "runtime": "claude", "machine": "worker-1", "can": []}
        hub.TEAM["agents"]["kam"] = {"role": "worker", "runtime": "claude", "machine": "worker-1", "can": [],
                                     "title": "Key Account Manager"}
        hub.TEAM["logins"] = {door: {"kind": "api_key", "env": "DOOR_BACKBLAZE_ACME_KEY",
                                     "title": "DOOR_BACKBLAZE_ACME_KEY"},
                              login: {"kind": "login", "title": "shop.example · ops@example.com"},
                              "bws://00000000-0000-4000-8000-00000000d1de": {"kind": "login",
                                                                              "title": "shop.com · ops@shop.com"},
                              "bws://00000000-0000-4000-8000-00000000d2de": {"kind": "login", "title": "Main"},
                              "bws://00000000-0000-4000-8000-00000000c0de": {"kind": "api_key", "title": "Stripe",
                                                                              "env": "STRIPE_SECRET_KEY"},
                              "bws://00000000-0000-4000-8000-00000000c1de": {"kind": "api_key", "title": "OpenAI",
                                                                              "env": "OPENAI_API_KEY"}}
        person = dict(reason="person", options=["Done", "Not now"])
        steps = ("In Founderizer on your Mac, open the vault entry DOOR_BACKBLAZE_ACME_KEY and replace its value with "
                 "keyID:applicationKey.")
        route = f'a new value of DOOR_BACKBLAZE_ACME_KEY comes through request_secret with failed="{door}"'
        for fields in (dict(person, title="Enter the Acme Backblaze key again", what_to_do=steps),
                       dict(reason="access", needs_access="a new Backblaze key", what_to_do=steps),
                       dict(reason="money", title="Upgrade the Backblaze plan", why="It costs 29 EUR a month.",
                            what_to_do=f"Pay on the plan page. {steps}"),
                       dict(person, what_to_do="Do the steps under Details.", details=steps),
                       dict(person, what_to_do="Open the vault entry DOOR_BACKBLAZE_ACME_KEY. Replace it with "
                                               "keyID:applicationKey."),
                       dict(person, what_to_do="Rotate DOOR_BACKBLAZE_ACME_KEY in the vault."),
                       dict(person, what_to_do="In Fleet Vault, replace DOOR_BACKBLAZE_ACME_KEY with "
                                               "keyID:applicationKey."),
                       dict(person, what_to_do="En Founderizer, abre la entrada del vault DOOR_BACKBLAZE_ACME_KEY y "
                                               "reemplaza su valor por keyID:applicationKey."),
                       # the same as numbered steps, or in two sentences: the place of an earlier line holds
                       dict(person, what_to_do="1. In Founderizer on your Mac, open the vault entry "
                                               "DOOR_BACKBLAZE_ACME_KEY.\n2. Replace its value with "
                                               "keyID:applicationKey."),
                       dict(person, what_to_do="1. Open Fleet Vault.\n2. Find DOOR_BACKBLAZE_ACME_KEY.\n3. Replace its "
                                               "value with keyID:applicationKey."),
                       dict(person, what_to_do="Open the vault entry DOOR_BACKBLAZE_ACME_KEY. Then replace its value "
                                               "with keyID:applicationKey."),
                       dict(person, what_to_do="1. Open the Secrets page.\n2. Open DOOR_BACKBLAZE_ACME_KEY.\n3. Press "
                                               "Replace and paste keyID:applicationKey."),
                       dict(person, what_to_do="1. Abre la bóveda.\n2. Busca DOOR_BACKBLAZE_ACME_KEY.\n3. Reemplaza "
                                               "su valor por keyID:applicationKey."),
                       dict(person, what_to_do="Open Fleet Vault, choose DOOR_BACKBLAZE_ACME_KEY and enter it again as "
                                               "keyID:applicationKey."),
                       # with the vault and the key's variable, any verb of typing, whatever its object
                       dict(person, what_to_do="In Founderizer on your Mac, open the vault entry "
                                               "DOOR_BACKBLAZE_ACME_KEY and paste keyID:applicationKey."),
                       dict(person, what_to_do="In Founderizer on your Mac, open the vault entry "
                                               "DOOR_BACKBLAZE_ACME_KEY and enter the key as keyID:applicationKey."),
                       dict(person, what_to_do="1. In Founderizer, open the vault entry DOOR_BACKBLAZE_ACME_KEY.\n2. "
                                               "Paste keyID:applicationKey into its field.\n3. Press Save."),
                       dict(person, what_to_do="1. En Founderizer, abre la entrada del vault DOOR_BACKBLAZE_ACME_KEY.\n"
                                               "2. Pega keyID:applicationKey en su campo.\n3. Pulsa Guardar."),
                       # the provider's page in a later step stops no earlier place for its value, "it" or a paste
                       dict(person, what_to_do="1. In Founderizer on your Mac, open the vault entry "
                                               "DOOR_BACKBLAZE_ACME_KEY.\n2. At "
                                               "https://secure.backblaze.com/app_keys.htm, click **Add a New "
                                               "Application Key** and paste keyID:applicationKey into the entry."),
                       dict(person, what_to_do="Open the vault entry DOOR_BACKBLAZE_ACME_KEY on your Mac. On "
                                               "Backblaze's page, make a new key, then replace its value with "
                                               "keyID:applicationKey."),
                       # the Spanish "it"
                       dict(person, what_to_do="Abre DOOR_BACKBLAZE_ACME_KEY en Fleet Vault. Reemplázalo con "
                                               "keyID:applicationKey."),
                       dict(person, what_to_do="Abre DOOR_BACKBLAZE_ACME_KEY en la bóveda y reemplázala por "
                                               "keyID:applicationKey."),
                       # a typed pair after an article or "new", and "your value" after another place
                       dict(person, what_to_do="Open DOOR_BACKBLAZE_ACME_KEY in Fleet Vault. Then paste the new "
                                               "keyID:applicationKey in its field."),
                       dict(person, what_to_do="1. Open the vault entry DOOR_BACKBLAZE_ACME_KEY.\n2. Type the "
                                               "keyID:applicationKey pair."),
                       dict(person, what_to_do="1. Open the vault entry DOOR_BACKBLAZE_ACME_KEY.\n2. At Backblaze, "
                                               "make a new key, then replace your value with it."),
                       # "for" after a verb of replacing, "for it" and "for the new ...", and a typed new value
                       dict(person, what_to_do="1. Open the vault entry DOOR_BACKBLAZE_ACME_KEY.\n2. Replace the old "
                                               "value for the new keyID:applicationKey."),
                       dict(person, what_to_do="1. Open the vault entry DOOR_BACKBLAZE_ACME_KEY.\n2. Replace the value "
                                               "for Backblaze with keyID:applicationKey."),
                       dict(person, what_to_do="1. Open the vault entry DOOR_BACKBLAZE_ACME_KEY.\n2. Replace its value "
                                               "for the Acme account with keyID:applicationKey."),
                       dict(person, what_to_do="1. Abre la entrada del vault DOOR_BACKBLAZE_ACME_KEY.\n2. Reemplaza su "
                                               "valor para Backblaze por keyID:applicationKey."),
                       dict(person, what_to_do="1. Open the vault entry DOOR_BACKBLAZE_ACME_KEY.\n2. Type the new "
                                               "value for Backblaze."),
                       # at the provider's page, the new value for the entry is the key's
                       dict(person, what_to_do="1. In Founderizer on your Mac, open the vault entry "
                                               "DOOR_BACKBLAZE_ACME_KEY.\n2. At "
                                               "https://secure.backblaze.com/app_keys.htm, click **Add a New "
                                               "Application Key** and paste the new value for the entry."),
                       dict(person, what_to_do="1. Open the vault entry DOOR_BACKBLAZE_ACME_KEY.\n2. At Backblaze, "
                                               "make a new key, then replace the value for the entry with "
                                               "keyID:applicationKey.")):
            with self.subTest(fields=fields):
                self.refused(route, **fields)
        stripe = 'a new value of STRIPE_SECRET_KEY comes through request_secret with failed='
        for todo in ("Open STRIPE_SECRET_KEY in Fleet Vault and type the key that Stripe shows.",
                     "Update STRIPE_SECRET_KEY in Fleet Vault with the new key from Stripe.",
                     # the app's own path with a part of its card, which is no other place
                     "1. Open the Secrets page.\n2. Open STRIPE_SECRET_KEY.\n3. On the Value row, press Replace and "
                     "paste the new key.",
                     "1. Abre la página de secretos.\n2. Abre STRIPE_SECRET_KEY.\n3. En Valor, pulsa Reemplazar y "
                     "pega la clave nueva.",
                     "1. Abre la bóveda.\n2. Abre STRIPE_SECRET_KEY.\n3. Reemplázalo con la clave nueva."):
            with self.subTest(todo=todo):
                self.refused(stripe, **person, what_to_do=todo)
        for todo in ("Open the Backblaze key in the vault and replace its value.",        # no name of the list
                     "1. Open Fleet Vault.\n2. Find the Backblaze key.\n3. Type the new value for it.",
                     "1. Open Fleet Vault.\n2. Open the Backblaze key.\n3. Replace its value for the new one from "
                     "Backblaze.",
                     "1. Abre la bóveda.\n2. Busca la clave de Backblaze.\n3. Escribe el nuevo valor para ella."):
            with self.subTest(todo=todo):
                self.refused('failed="<its reference>"', reason="access", needs_access="the Backblaze key",
                             what_to_do=todo)
        for todo in ("Type a new password for the shop.example login in Fleet Vault.",
                     "Update your password for shop.example in Fleet Vault.",
                     "1. Open Fleet Vault.\n2. Find the shop.example login.\n3. Type its new password."):
            with self.subTest(todo=todo):
                self.refused(f'site="https://shop.example" and failed="{login}"', **person,
                             title="A new password for the shop.example login", what_to_do=todo)
        self.refused(f"Give it as secret:{login}", reason="access",
                     needs_access="a new password for the shop.example login")
        # words that name another account's address mean another login of that site, which the list does not hold
        other = "a login at shop.example for billing@example.com"
        self.assertIsInstance(self.card(reason="access", needs_access=other), int)
        for fields in (dict(what_to_do="Type the new API key as your answer."),
                       dict(what_to_do="Enter your Stripe password in your reply."),
                       dict(what_to_do="Put the new key here in your answer."),
                       dict(what_to_do="Type the new API key below."), dict(what_to_do="Enter the new API key here."),
                       dict(what_to_do="Type the API key in this card."), dict(what_to_do="Tell me the new API key."),
                       dict(what_to_do="Escribe la nueva clave API como respuesta."),
                       dict(what_to_do="Escribe la clave de Stripe como respuesta."),
                       dict(what_to_do="Pega la clave API de Stripe aquí."), dict(what_to_do="Dame la clave."),
                       dict(what_to_do="Envía la clave."), dict(what_to_do="Mándame la contraseña."),
                       dict(what_to_do="Give me the token."), dict(what_to_do="Copy the new API key into your answer."),
                       dict(what_to_do="Tell me the password here."),
                       dict(what_to_do="Tell me your password in the answer."),
                       dict(what_to_do="Tell me the password in your reply."),
                       dict(what_to_do="Tell me the new API key now."),
                       dict(what_to_do="Give me the new Stripe key please."),
                       # words after the key, a clause of the one who gives it, "it", and the Spanish "aquí"
                       dict(what_to_do="Type the key from Stripe as your answer."),
                       dict(what_to_do="Enter the new API key from the Stripe page as your answer."),
                       dict(what_to_do="Type the password for shop.com as your answer."),
                       dict(what_to_do="Reply with the API key that Stripe shows."),
                       dict(what_to_do="Answer with the key Stripe gave you."),
                       dict(what_to_do="Reply with your new password once you have reset it."),
                       dict(what_to_do="Type the key that Stripe shows as your answer."),
                       dict(what_to_do="Copy the new token and paste it as your answer."),
                       dict(what_to_do="Pega aquí la nueva clave."), dict(what_to_do="Escribe aquí la contraseña."),
                       dict(what_to_do="Escribe la clave que te da Stripe como respuesta."),
                       dict(what_to_do="Insert the password as your answer."),
                       dict(what_to_do="Input the API key in your reply."),
                       dict(what_to_do="Inserta la clave como respuesta."),
                       dict(what_to_do="Type the new API key, all of it, as your answer."),
                       dict(what_to_do="Type the new Stripe API key exactly as your answer."),
                       dict(what_to_do="Copy the new token from the Stripe page and paste it as your answer."),
                       # the details' own "Fleet Vault" exempts no ask in what_to_do
                       dict(what_to_do="Send the new API key to Customer Support.",
                            details="The old key is in Fleet Vault."),
                       # the details as steps
                       dict(what_to_do="Do the steps under Details.", details="Send the API key."),
                       dict(what_to_do="Do the steps under Details.", details="Please send the new password."),
                       dict(what_to_do="Do the steps under Details.", details="Share the token with me."),
                       dict(what_to_do="Do the steps under Details.", details="Envía la clave."),
                       dict(what_to_do="Do the steps under Details.", details="Now send the API key."),
                       dict(what_to_do="Do the steps under Details.", details="Please, send the API key."),
                       dict(what_to_do="Do the steps under Details.", details="If you have it, send the API key."),
                       dict(what_to_do="Do the steps under Details.",
                            details="Then send the key to Stripe's support only if they ask for it again."),
                       dict(what_to_do="Do the steps under Details.", details="Please send the new password, thanks."),
                       dict(what_to_do="Do the steps under Details.", details="Comparte la clave conmigo."),
                       # a way to send it, a Spanish "de", and a comma that is no contrast
                       dict(what_to_do="Do the steps under Details.", details="Send the API key by email."),
                       dict(what_to_do="Do the steps under Details.", details="Paste the API key in the chat."),
                       dict(what_to_do="Do the steps under Details.", details="Send the new password over Slack."),
                       dict(what_to_do="Do the steps under Details.", details="Send the API key via WhatsApp."),
                       dict(what_to_do="Do the steps under Details.", details="Send the key and the key ID to Ada."),
                       dict(what_to_do="Do the steps under Details.", details="Envía la clave por correo."),
                       dict(what_to_do="Do the steps under Details.", details="Envía la contraseña en el chat."),
                       dict(what_to_do="Do the steps under Details.", details="Envía la clave de la API."),
                       dict(what_to_do="Do the steps under Details.", details="Envía la clave de acceso."),
                       dict(what_to_do="Do the steps under Details.", details="Send the new, rotated API key."),
                       dict(what_to_do="Do the steps under Details.", details="Send, as soon as you can, the API key."),
                       dict(what_to_do="Do the steps under Details.", details="Envía la clave nueva por correo."),
                       dict(what_to_do="Envía a David la contraseña."),
                       dict(what_to_do="Envía la clave de Stripe a soporte."),
                       dict(why="The Stripe key on the Secrets page was revoked.",
                            what_to_do="Give the new key as your answer."),
                       dict(why="The key on the Secrets page was revoked.", what_to_do="Reply with the new key."),
                       dict(what_to_do="Do the steps under Details.", details="Type the new API key as your answer.")):
            with self.subTest(fields=fields):         # the refusal quotes none of the words, which can hold a value
                said = self.refused("is never sent in words", **{**person, "title": "The shop's key", **fields})
                self.assertNotIn(fields.get("details") or fields["what_to_do"], said)
        for fields in (dict(what_to_do="Answer when the new API key is in the vault."),
                       dict(what_to_do="Type Yes as your answer."),
                       dict(what_to_do="Give the key's name as your answer."),
                       dict(what_to_do="Type your password at its keyboard."),
                       dict(what_to_do="Paste the shop's key into Fleet Vault on your Mac."),
                       dict(what_to_do="Enter the Mac's password at studio-1's own keyboard."),
                       dict(what_to_do="Approve the sign-in to shop.example on your phone."),
                       dict(what_to_do="Escribe Sí como respuesta."),
                       # a value at a site that a login of the list names, and a box of that name, are no secret's
                       dict(what_to_do="At your registrar, open shop.com and change the value of its MX record to "
                                       "mx.shop-mail.net."),
                       dict(what_to_do="At your registrar, add a TXT record for shop.example and paste the value "
                                       "v=DKIM1; p=abc."),
                       dict(why="The agent must change the password of shop.com, which sends a code to your phone.",
                            what_to_do="Approve the code on your phone."),
                       dict(what_to_do="At the Main box, set the value to 3."),
                       # a password at a machine's keyboard, with the vault in another sentence; another vault
                       dict(title="studio-1 waits at its login window",
                            why="It restarted, and its vault gives agents no key until its user is signed in.",
                            what_to_do="At studio-1's own keyboard, type the password of its user."),
                       dict(what_to_do="En el teclado de studio-1, escribe la contraseña de su usuario."),
                       dict(what_to_do="In Azure Key Vault, update the value of the setting allowPublicAccess to "
                                       "false."),
                       # the word "vault" that is no place, also before "it"; the value of something else
                       dict(what_to_do="At studio-1's own keyboard, type the password of its user, so that its vault "
                                       "can start."),
                       dict(what_to_do="studio-1 restarted, and its vault waits for its user's password. At studio-1's "
                                       "own keyboard, enter it."),
                       dict(what_to_do="En el teclado de studio-1, escribe la contraseña de su usuario; después su "
                                       "vault arranca."),
                       dict(what_to_do="At studio-1's keyboard, sign in so its vault opens. Then set the new value of "
                                       "the screen saver to never."),
                       # the hub's own route of a grant on the Secrets page (secret_route)
                       dict(what_to_do="On the Secrets page, set STRIPE_SECRET_KEY to Uses it for Ada."),
                       dict(what_to_do="Open STRIPE_SECRET_KEY on the Secrets page. Change it so that Ada can use it."),
                       # "key" as an adjective, and a count or a policy of a secret, ask for no value
                       dict(what_to_do="Tell me the key date for the launch."),
                       dict(what_to_do="Tell me the key points to cover."),
                       dict(what_to_do="Dime la palabra clave principal."),
                       dict(what_to_do="Escribe la palabra clave como respuesta."),
                       dict(what_to_do="Dime la fecha clave del lanzamiento."),
                       dict(what_to_do="Tell me the token count."),
                       dict(what_to_do="Tell me the password policy of shop.com."),
                       dict(what_to_do="Dime el nombre de la clave."), dict(what_to_do="Tell me the key that fails."),
                       dict(what_to_do="Reply with the key date."), dict(what_to_do="Responde con la fecha clave."),
                       dict(what_to_do="Answer with Yes when the key is in the vault."),
                       dict(what_to_do="Reply with which key fails."),
                       # a password after a vault that names no login, at a keyboard, at the owner's own account
                       dict(what_to_do="The agents' keys in the vault wait for studio-1. At studio-1's own keyboard, "
                                       "type its user's password."),
                       dict(what_to_do="Stripe refused STRIPE_SECRET_KEY after the leak. Change your password at "
                                       "https://dashboard.stripe.com, then approve the code on your phone."),
                       dict(what_to_do="STRIPE_SECRET_KEY falla desde ayer. En el panel de Stripe, cambia tu "
                                       "contraseña y aprueba el código en tu teléfono."),
                       dict(what_to_do="1. In Founderizer, open the Secrets page and check that STRIPE_SECRET_KEY is "
                                       "there.\n2. At Stripe, change your password, and type the new password at "
                                       "Stripe only."),
                       dict(what_to_do="On the Secrets page, edit STRIPE_SECRET_KEY and share it with Ada."),
                       # a typing verb on no value: the Mac's password, a note, an agent, a key, "press Enter", "type"
                       dict(what_to_do="On the Secrets page, open STRIPE_SECRET_KEY, choose Uses it for Ada, and enter "
                                       "your Mac password when macOS asks."),
                       dict(what_to_do="1. Open the Secrets page.\n2. Open STRIPE_SECRET_KEY.\n3. Type the note: the "
                                       "live key of the shop."),
                       dict(what_to_do="En la página de secretos, abre STRIPE_SECRET_KEY y escribe una nota: la clave "
                                       "de la tienda."),
                       dict(what_to_do="Open the vault entry STRIPE_SECRET_KEY and enter Ada under Who can use it."),
                       # an agent by its role, which team.json's "title" holds (the label that the owner reads since
                       # F16 is its name): a role that begins with "key" is no key
                       dict(what_to_do="Open the vault entry STRIPE_SECRET_KEY and enter the Key Account Manager under "
                                       "Who can use it."),
                       dict(what_to_do="1. Open the Secrets page.\n2. Open STRIPE_SECRET_KEY.\n3. Set Ada to Uses it "
                                       "and press Enter."),
                       dict(what_to_do="On the Secrets page, enter STRIPE_SECRET_KEY's card and set Ada to Uses it."),
                       dict(what_to_do="On the Secrets page, check the type of STRIPE_SECRET_KEY: if it says Reads it, "
                                       "set Ada to Uses it."),
                       # an answer shape's nouns after the key, and the details and options read for the answer only
                       dict(what_to_do="Type the key name as your answer."),
                       dict(what_to_do="Type the token count as your answer."),
                       dict(what_to_do="Type the key date as your answer."),
                       dict(options=["Send the password reset link", "Ask them to wait"]),
                       dict(details="Stripe will send the new key to the account's email."),
                       dict(details="Send the password reset link to ops@shop.com."),
                       dict(details="When it is ready, Stripe will send the new key to the account's email."),
                       dict(details="If the link expired, send the password reset link again."),
                       dict(details="Now Stripe sends the new token to ops@shop.com."),
                       dict(details="Send the key rotation notice to the team."),
                       # a key ID, and "key" as an adjective in a step of the details
                       dict(title="Stripe changes its API", options=["Switch now", "Wait"],
                            details="If Backblaze support asks, send the key ID, not the application key."),
                       dict(details="Send the budget for the key launch to Finance."),
                       dict(details="Send the key account list to Finance."),
                       dict(details="1. Send the key findings to the board."),
                       dict(details="Then send the key partner contract to legal."),
                       dict(details="Send the key ID, but never the application key."),
                       dict(details="Envía el ID de la clave, no la clave de aplicación."),
                       dict(details="Envía el ID de la clave a soporte."),
                       dict(what_to_do="Envía el ID de la clave a soporte."),
                       dict(details="Send the order id to Finance."),
                       dict(what_to_do="Envía las palabras clave al equipo de SEO."),
                       dict(what_to_do="Envía los puntos clave del informe a Ada."),
                       dict(details="Send Ada the report, and keep the key in the vault."),
                       # a replace of the value for something else at a provider, and the Spanish budget and VAT cards
                       dict(what_to_do="STRIPE_SECRET_KEY works again. At https://dashboard.stripe.com/prices, replace "
                                       "the value for the Pro plan with 29 EUR."),
                       dict(what_to_do="OPENAI_API_KEY reached its limit. At "
                                       "https://platform.openai.com/settings/limits, replace the value for the monthly "
                                       "budget with 200 USD."),
                       dict(what_to_do="1. Abre la entrada del vault OPENAI_API_KEY.\n2. En OpenAI, escribe el nuevo "
                                       "valor para el presupuesto mensual."),
                       # "for the key's ..." or "para la clave de ..." names something of the key's, not the key
                       dict(what_to_do="OPENAI_API_KEY reached its monthly limit. At "
                                       "https://platform.openai.com/settings/limits, type the new value for the key's "
                                       "monthly budget and press Save."),
                       dict(what_to_do="OPENAI_API_KEY alcanzó su límite mensual. En "
                                       "https://platform.openai.com/settings/limits, escribe el nuevo valor para la "
                                       "clave de presupuesto mensual."),
                       dict(what_to_do="1. Abre la entrada del vault STRIPE_SECRET_KEY y lee su nota.\n2. En la "
                                       "página de impuestos de Stripe, pega el nuevo valor para el IVA."),
                       # the new value for something else after a vault step, at another place
                       dict(what_to_do="1. Open Fleet Vault.\n2. Check that OPENAI_API_KEY is there.\n3. Then set the "
                                       "new value for the monthly budget to 200 USD."),
                       dict(what_to_do="1. Open the vault entry STRIPE_SECRET_KEY and read its note.\n2. On Stripe's "
                                       "tax page, paste the new value for the VAT rate."),
                       # sharing a key with an agent is a grant
                       dict(title="Give Ada the Stripe key", what_to_do="Do the steps under Details.",
                            details="Share the key with Ada so that she can answer refunds."),
                       dict(title="Give Ada the Stripe key", what_to_do="Do the steps under Details.",
                            details="2. Share the API key with Customer Support."),
                       dict(what_to_do="Type the token count, then the budget, as your answer."),
                       # the new value for something else at a provider, after a key's name
                       dict(what_to_do="OPENAI_API_KEY reached its monthly limit. At "
                                       "https://platform.openai.com/settings/limits, type the new value for the "
                                       "monthly budget and press Save."),
                       dict(what_to_do="STRIPE_SECRET_KEY works again. At https://dashboard.stripe.com/prices, type "
                                       "the new value for the Pro plan."),
                       dict(what_to_do="STRIPE_SECRET_KEY works again. At https://dashboard.stripe.com/prices, type "
                                       "your new value for the Pro plan."),
                       dict(what_to_do="STRIPE_SECRET_KEY is fine. On Stripe's tax page, paste the new value for the "
                                       "VAT rate."),
                       # a noun after "key" or "token" before the answer, or before "and type it"
                       dict(what_to_do="Type the key message as your answer."),
                       dict(what_to_do="Type the token budget as your answer."),
                       dict(what_to_do="Put the monthly token budget in your reply."),
                       dict(what_to_do="Enter the token cap as your answer."),
                       dict(what_to_do="Choose the key message for the launch and type it as your answer."),
                       dict(what_to_do="Pick the token budget for next month and type it as your answer."),
                       dict(what_to_do="Decide the key date and type it as your answer."),
                       dict(what_to_do="Choose the key date for the launch and type it as your answer."),
                       dict(what_to_do="Pick the key date and type it here."),
                       dict(what_to_do="Note the key points and type them as your answer."),
                       # a link is no typed value
                       dict(what_to_do="In Fleet Vault, STRIPE_SECRET_KEY is fine. At "
                                       "https://dashboard.stripe.com/webhooks, paste https://shop.example/hook as the "
                                       "endpoint."),
                       # a report of a failed attempt asks for nothing
                       dict(title="Switch Stripe to its new API?", options=["Switch now", "Wait"],
                            why="Customer Support could not update the value in the vault."),
                       dict(title="Switch Stripe to its new API?", options=["Switch now", "Wait"],
                            details="Customer Support could not update the value in the vault.")):
            with self.subTest(fields=fields):
                self.assertIsInstance(self.card(**{**person, "title": "The shop's key", **fields}), int)

    def test_access_that_an_agent_holds_or_the_manager_can_grant_never_reaches_the_owner(self):
        # the fleet's GitHub App reaches acme's repositories, so dev can use acme/web: with no App, a repository's
        # card goes to the owner, who connects GitHub first (team_repo_owner_step)
        for held in (patch.object(hub, "github_app", lambda: ("7", "key")),
                     patch.dict(hub.GITHUB_REACH, {"at": hub.now(), "reading": False, "reach": {
                         "pages": {}, "all": {"acme"}, "repos": set(), "install": None}})):
            held.start()
            self.addCleanup(held.stop)
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
        # a key's value is what the hub never sees: a revoked one is the owner's to replace, in request_secret's
        # secure card (failed), never by an item whose steps send them into the vault (the key badge and key replace,
        # 21 November 2026)
        key = "bws://00000000-0000-4000-8000-00000000c0de"
        hub.TEAM["logins"] = {key: {"kind": "api_key", "env": "SHOP_KEY", "title": "Shop API"}}
        hub.TEAM["agents"]["dev"]["secrets"] = {key: "use"}
        self.assertIn(f'request_secret with failed="{key}"',
                      self.refused("dev (use) holds", reason="access", needs_access=f"secret:{key}"))
        # with the details that request_secret asks of a key (SECRET_NEEDS_STEPS), so that the route takes one call
        self.assertIn(f'request_secret with failed="{key}" and details (how the owner makes the new key)', self.refused(
            "Not raised: a new value of", reason="access", needs_access=f"secret:{key}", needs_level="value"))
        # a site of the table is the manager's to switch off
        hub.TEAM["logins"][key]["table"] = {"row": "shop", "on": True}
        for level in ("value", "placeholder"):
            self.assertIn('switch_key_site with to="off"', self.refused(
                "Not raised:", reason="access", needs_access=f"secret:{key}", needs_level=level))
        del hub.TEAM["logins"][key]["table"]
        # a site that the owner set, held as a placeholder that a program cannot use, is the one case that only an
        # item settles; value never raises it, because the hub cannot tell a revoked value from that
        self.refused("no agent holds SHOP_KEY as a placeholder", reason="access", needs_access=f"secret:{key}",
                     needs_level="placeholder")
        # by the rule (lifecycle.key_swap), for a worker's sessions and for the manager's own, on a server with no word
        # of the owner's yet: a bug that counts only workers and leads, or reads that word, refuses this item with
        # "its sessions hold the key itself" and sends the owner to type a new value of a good key
        hub.TEAM["logins"][key]["site"] = "https://api.shop.example"
        for reader in ("dev", "manager"):
            with self.subTest(reader=reader):
                hub.TEAM["agents"]["dev"]["secrets"][key] = "read" if reader == "dev" else "use"
                hub.TEAM["agents"]["manager"]["secrets"] = {key: "read"} if reader == "manager" else {}
                self.assertIn('give needs_level "placeholder"', self.refused(
                    f'failed="{key}"', reason="access", needs_access=f"secret:{key}", needs_level="value"))
                self.assertIsInstance(self.card(reason="access", needs_access=f"secret:{key}",
                                                needs_level="placeholder"), int)
        said = self.refused("holds", reason="access", needs_access=f"secret:{key}")     # its route, said once
        self.assertEqual(said.count('give needs_level "placeholder"'), 1, said)
        login = "bws://00000000-0000-4000-8000-00000000d0de"
        hub.TEAM["logins"][login] = {"kind": "login", "title": "shop.example", "username": "ops@example.com"}
        hub.TEAM["agents"]["dev"]["secrets"][login] = "use"
        self.assertIn(f'failed="{login}"', self.refused('kind "login"', reason="access",
                                                         needs_access=f"secret:{login}", needs_level="value"))
        # a login that the owner replaced: the route of the newer one, while the list has it, with its kind and site
        newer = "bws://00000000-0000-4000-8000-00000000d1de"
        hub.TEAM["logins"][newer] = {"kind": "login", "title": "shop.example · ops@example.com"}
        hub.q("INSERT INTO needs(title,why,todo,raised,by,kind,secret,answer,answered) VALUES('t','w','d',?,"
              "'manager','secret',?,'Saved',?)",
              (hub.now(), json.dumps({"kind": "login", "failed": login, "saved": newer}), hub.now()))
        self.assertIn(f'kind "login", site="https://shop.example" and failed="{newer}"', self.refused(
            f"gave a new password for {login} already, as {newer}", reason="access", needs_access=f"secret:{login}",
            needs_level="value"))
        del hub.TEAM["logins"][newer]                       # the owner removed it since
        said = self.refused("not a login of the list now", reason="access", needs_access=f"secret:{login}",
                            needs_level="value")
        self.assertIn('site="https://shop.example", without failed', said)
        self.assertNotIn(f'failed="{newer}"', said)
        hub.q("DELETE FROM needs WHERE kind='secret'")
        # the owner renamed it, or a title only looks like a host: no site to name
        for title in ("Shop", "Node.js", "v2.0 · ops@example.com", "."):
            with self.subTest(title=title):
                hub.TEAM["logins"][login]["title"] = title
                said = self.refused("names no site that the hub can tell", reason="access",
                                    needs_access=f"secret:{login}", needs_level="value")
                self.assertNotIn("https://", said)
        # an address is a site too, and so is a host in capitals, as an import may write it
        for title, site in (("10.0.0.5 · ops@example.com", "10.0.0.5"), ("SHOP.EXAMPLE · ops", "shop.example")):
            with self.subTest(title=title):
                hub.TEAM["logins"][login]["title"] = title
                self.assertIn(f'site="https://{site}" and failed="{login}"', self.refused(
                    'kind "login"', reason="access", needs_access=f"secret:{login}", needs_level="value"))
        app_key = "bws://00000000-0000-4000-8000-00000000e0de"
        hub.TEAM["logins"][app_key] = {"kind": "api_key", "env": "GITHUB_APP_ACME_KEY", "title": "GitHub App"}
        hub.TEAM["agents"]["dev"]["secrets"][app_key] = "use"
        # the hub's github_key item is open only in the renewal of the key that it held: at any other time the owner
        # is told, and a bug that says "the hub asks you" leaves the manager waiting for a message that never comes
        self.assertIn("tell the owner with message_owner", self.refused(
            "is a GitHub App's key", reason="access", needs_access=f"secret:{app_key}", needs_level="value"))
        self.refused("needs_level value is for a key or a login of the fleet", reason="access",
                     needs_access="repo:acme/web", needs_level="value")
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

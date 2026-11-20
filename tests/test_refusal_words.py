"""A refusal's code and its names (refusal_words.py, and the places of hub.py that use it).

The hub keeps its English in `error` and adds a `code` beside it, and `names` for the values inside the words. An app
shows its own words for a code that it knows and `error` for another, so the English must never change, and each
code must stay the one sentence that it was given for. This file holds that: the table, the places of hub.py that
name a code, the old English of every place that was converted (written out here, so that a change of the table is a
change of this file too), and the three ways that an exception reaches an answer.

It needs no fleet and no hub process: a database in memory that never syncs to the disk, a handler with no socket, and
one test hub (OwnerAPI) for a route of the real server."""
import ast
import json
import os
import re
import sqlite3
import string
import tempfile
import unittest
import uuid
from unittest.mock import patch

import hub
import refusal_words
from refusal_words import CODE, HOLE, WORDS, Coded, answer, fields, holes, refusal_body, shown, words
from test_ui_api import OwnerAPI, own_files, quick
from leftovers import ROOT

KIT = ROOT

# The English of each code as hub.py wrote it before it had codes, with a name in `{}` where the words hold one. The
# table must give each of these word for word: an app shows `error` to every code that it does not know, and the
# owner's own AI, the logs and the old apps read it.
OLD = {
    "hub_changed": "hub generation changed; refresh state",
    "hub_changed_sending": "hub generation changed; refresh state before sending",
    "team_changed": "team.json changed meanwhile; reload it",
    "team_changed_lines": "team.json changed meanwhile; reload the reporting lines",
    "no_such_agent": "no such agent",
    "no_such_server": "no such server",
    "no_such_task": "no such task",
    "login_as_text": "a registered login cannot be sent as text",
    "login_as_file": "a registered login cannot be sent as a file",
    "login_not_shown": "registered login text cannot be displayed",
    "command_reused": "request_id was already used for a different command",
    "command_reused_message": "request_id was already used for an owner message; send the answer with a new one",
    "command_reused_file": "request_id was already used for another file",
    "command_reused_content": "request_id was already used for different content or recipient",
    "command_interrupted": "this command was interrupted and the hub does not know what came of it. Read the thing it "
                           "was about, and send the command again with a new request_id if it did not take effect",
    "revision_unreadable": "the hub cannot read its own revision",
    "knowledge_unread": "the knowledge files cannot be read now; try again in a moment",
    "server_silent": "{server} sent no reading in the last 10 minutes: check that it is on",
    "server_no_service": "{server} has no server service: it did not join with a join code",
    "request_answered": "owner request is already answered",
    "request_unknown": "owner request does not exist",
    "request_unknown_ended": "owner request does not exist: a request whose task ended is gone with it",
    "not_owner_device": '{address} is not an owner device. See "owner_devices" in team.json.',
    "not_owner_device_no_code": "{address} is not an owner device, and that is not a code for a new one",
    "agent_mid_turn": "{agent} is in the middle of a turn. Move it when the turn ends.",
    "agent_open_signin": "{agent} has an open sign-in. Finish it or let it run out, then try again.",
    "time_passed": "this time has passed; change the time first",
    "google_file_mode": "the Google file of the hub must be a regular file of the hub user with mode 600",
    "google_file_unreadable": "the Google file of the hub cannot be read: it is not a JSON object with accounts",
    "google_file_key": "the hub cannot read the key of its Google file now",
    "google_file_lost": "the Google file of the hub does not open with its key: connect each Google account again",
    "google_no_client": "This hub's release has no Google client. Update the hub, then connect again.",
    "google_no_secret": "Founderizer's Google app cannot be read from founderizer.com now, so nothing was started. Try "
                        "again in a few minutes.",
    "connect_stale": "This Connect expired, or another one took its place. Start Connect again.",
    "google_refused": "Google refused: {reason}. Start Connect again.",
    "google_revoked_during": "A Disconnect of this account came during this Connect, so nothing was connected. Start "
                             "Connect again.",
    # the lane "Drive folders" (POST /ui/team/google with folder)
    "drive_folder_link": "That is not the link of a Drive folder.",
    "drive_folder_account": "{account} is not connected for Google Drive now. Connect it again.",
    "drive_folder_unseen": "{account} cannot open this folder. Share it with {account}, or connect the account that "
                           "has it.",
    "drive_folder_file": "That is the link of a file, not of a folder.",
    "drive_folder_google": "Google did not answer about this folder: {reason}. Try again.",
    # a grant of one of the product's own repositories (the area "Vault, keys and access", 20 November 2026)
    "repo_vendor": "The door refuses {repo} in every fleet, so no grant of it works: leave it out.",
    # the lane "Any MCP server: install and sign-in" (UI-API.md 1.187)
    "package_unknown": "{registry} has no package {name}",
    "package_unread": "{registry} did not give the record of {name} ({http_status})",
    "package_registry_away": "{registry} cannot be reached now",
    "package_record_large": "the record of {name} at {registry} is larger than {megabytes} MB",
    "package_no_record": "{registry} gave no record of {name}",
    "package_no_version": "{registry} has no version {version} of {name}",
    "package_too_new": "{name} {version} was published on {day}, less than {days} days ago",
    "package_too_new_older": "{name} {version} was published on {day}, less than {days} days ago; the newest version "
                             "that is older is {newest}",
    "package_none_old": "{name} has no release that is at least {days} days old",
    "mcp_registry_away": "the MCP Registry cannot be reached now",
    "mcp_registry_no_list": "the MCP Registry gave no list of servers",
    "mcp_no_endpoints": "the MCP server {server} gave no OAuth endpoints: {reason}",
    "server_name_kept": "This server is called {name} in Tailscale, and Fleet keeps that name for itself. Rename this "
                        "server in Tailscale, then run the line again.",
    # an agent's browser on a Linux server (build plan 04, S3; UI-API.md 1.218): its Shell box (D2), a server that runs
    # none (D8), and a server with no room for it (D6)
    "browser_shell_off": "{agent} cannot have a browser on a Linux server while its Shell box is off: turn its Shell "
                         "box on, or its Browser box off",
    "browser_server": "{server} runs no browser for an agent: in this version only a Linux server with x86 Ubuntu "
                      "24.04 or 26.04 that is not the hub's own server runs one",
    "browser_no_room": "{server} has no room for the browser of {agent} beside its other agents: turn its Browser box "
                       "off first, or move it to a server with more memory",
    "no_such_person": "no such person",
    "person_blocked": "you blocked this person",
    "person_handles_most": "a person has at most {most} handles",
    "agent_no_telegram_bot": "{agent} has no Telegram bot",
    "bot_name_unknown": "the bot has not said its name yet: try again when the bot is connected",
    "token_bot_account": "a token is for a Discord or Telegram account",
    # Take over for an agent on a Linux server (build plan 04, S6; UI-API.md 1.225)
    "takeover_closed": "This step is answered or no longer open",
    "takeover_no_screen": "{agent}'s screen cannot be opened now: its server or its Founderizer is not ready for it",
    "takeover_late": "{agent}'s server did not open its screen in time: press Take over again",
    "takeover_no_browser": "{agent}'s browser does not run now, so there is no screen to take over",
    "takeover_provider": "{agent}'s browser shows an AI provider's site, which is never taken over",
    "takeover_screen_failed": "{agent}'s server could not share its screen: press Take over again",
}

# The places of hub.py that were converted to a code, by the function that holds each: the scan of 16 November 2026
# (an `ast` search of every route of the owner API) and the seven reads of the phone that it did not list. A place
# keeps its code: a place that moves to another code, or loses it, fails here. A lane may add codes to these functions.
SITES = {
    'add_server_agent': {'team_changed': 1},
    'add_server_refusal': {'no_such_server': 1, 'server_no_service': 1, 'server_silent': 1},
    'answer_secret': {'command_reused_message': 1, 'request_answered': 1, 'request_unknown_ended': 1},
    'attachment_check': {'login_as_file': 1},
    'command_run': {'command_interrupted': 1, 'command_reused': 1, 'hub_changed_sending': 1, 'login_as_text': 1},
    'enroll_new_device': {'not_owner_device_no_code': 1},
    'google_file_refusal': {'google_file_key': 1, 'google_file_lost': 1, 'google_file_mode': 1,
                            'google_file_unreadable': 1},
    'google_folder_found': {'drive_folder_account': 1, 'drive_folder_file': 1, 'drive_folder_google': 1,
                            'drive_folder_unseen': 1},
    'google_folder_id': {'drive_folder_link': 1},
    'grant_server': {'no_such_agent': 1},
    'join_server': {'server_name_kept': 1},       # a server named door (C49)
    'key_swap_entry': {'no_such_server': 1},      # Part B of the key swap: the 404 of both of its routes
    'knowledge_add': {'revision_unreadable': 1},
    'knowledge_content': {'login_as_text': 1},
    'knowledge_delete': {'revision_unreadable': 1},
    'knowledge_replace': {'revision_unreadable': 1},
    'mcp_package_lookup': {'package_no_record': 1, 'package_no_version': 1, 'package_none_old': 1,
                           'package_record_large': 1, 'package_registry_away': 1, 'package_too_new': 1,
                           'package_too_new_older': 1, 'package_unknown': 1, 'package_unread': 1},
    'mcp_registry_find': {'mcp_registry_away': 1, 'mcp_registry_no_list': 1},
    'move_agent': {'agent_mid_turn': 1, 'agent_open_signin': 1, 'no_such_agent': 1, 'no_such_server': 1,
                   'server_no_service': 1, 'server_silent': 1, 'team_changed': 1},
    'need_give_press': {'request_answered': 1},  # the lane "Give on a card": a Give whose agent left the fleet
    'new_invite_code': {'agent_no_telegram_bot': 1, 'bot_name_unknown': 1, 'no_such_person': 1, 'person_blocked': 1,
                        'person_handles_most': 1},     # a person's Telegram invite
    'older_read': {'hub_changed': 1},              # GET /ui/tasks/older (owner API 1.254)
    'person_remove': {'no_such_person': 1},
    'phone_chat': {'hub_changed': 1, 'no_such_agent': 1},
    'phone_ended': {'hub_changed': 1},
    'phone_knowledge': {'hub_changed': 1, 'knowledge_unread': 1},
    'phone_mobile': {'hub_changed': 1},
    'phone_submit': {'command_reused_content': 2, 'hub_changed_sending': 1, 'login_as_text': 3, 'request_answered': 1,
                     'request_unknown': 1},
    'phone_task': {'hub_changed': 1, 'no_such_task': 1},
    'prepare_server_agent': {'no_such_agent': 1, 'no_such_server': 1, 'server_no_service': 1, 'server_silent': 1},
    'remove_agent': {'no_such_agent': 1, 'team_changed': 1},
    'remove_server': {'no_such_server': 1, 'team_changed': 1},
    'rename_agent': {'agent_open_signin': 1, 'no_such_agent': 1, 'server_silent': 1, 'team_changed': 1},
    'save_access': {'team_changed': 1},
    'save_agent_settings': {'no_such_agent': 1, 'team_changed': 1},
    # build plan 04, S3 (UI-API.md 1.218)
    'browser_rule': {'browser_shell_off': 1, 'browser_server': 1}, 'browser_box_refusal': {'browser_server': 1},
    'browser_move_refusal': {'browser_no_room': 1, 'browser_shell_off': 1},
    # build plan 04, S6 (UI-API.md 1.225)
    'takeover_open': {'takeover_closed': 2, 'takeover_no_screen': 1, 'takeover_late': 1, 'takeover_no_browser': 1,
                      'takeover_provider': 1, 'takeover_screen_failed': 1},
    'save_grant': {'no_such_agent': 1},
    'save_integration': {'team_changed': 1},
    'save_lines': {'team_changed_lines': 1},
    'save_profile': {'revision_unreadable': 1},
    'save_resource': {'repo_vendor': 1},
    'save_runtime': {'no_such_agent': 1, 'team_changed': 1},
    'save_team_entry': {'team_changed': 1},
    'save_vault': {'no_such_agent': 1, 'team_changed': 1},
    'save_vault_create': {'no_such_agent': 1, 'team_changed': 1},
    'server_key_swap': {'team_changed': 1},
    'set_shape': {'team_changed': 1},
    'skill_remove': {'revision_unreadable': 1},
    'start_machine_login': {'no_such_agent': 1},
    'take_resource': {'no_such_agent': 1},
    'task_artifacts': {'login_not_shown': 2},
    'task_control_act': {'no_such_task': 1},
    'task_steer_act': {'no_such_task': 1},
    'ui_agent_messages': {'hub_changed': 1},
    'ui_artifacts': {'hub_changed': 1, 'no_such_task': 1},
    'ui_attachment_file': {'hub_changed': 1},
    'ui_attachment_upload': {'command_reused_file': 1, 'hub_changed_sending': 1},
    'ui_backup': {'hub_changed': 1},
    'ui_capacity': {'hub_changed': 1},
    'ui_chat_apps': {'hub_changed': 1},
    'ui_chat_link_state': {'hub_changed': 1},
    'ui_chat_token': {'token_bot_account': 1},
    'ui_checks': {'hub_changed': 1},
    'ui_connect': {'hub_changed': 1},
    'ui_conversation': {'hub_changed': 1},
    'ui_conversations': {'hub_changed': 1},
    'ui_costs': {'hub_changed': 1},
    'ui_diagnostics': {'hub_changed': 1},
    'ui_door': {'hub_changed': 1},
    'ui_events': {'hub_changed': 1, 'no_such_task': 1},
    'ui_github_repos': {'hub_changed': 1},
    'ui_google_connect': {'google_no_client': 1, 'google_no_secret': 1},
    'ui_google_finish': {'connect_stale': 1, 'google_refused': 1, 'google_revoked_during': 1},
    'ui_goal': {'hub_changed': 1},
    'ui_health': {'hub_changed': 1},
    'ui_history': {'hub_changed': 1},
    'ui_machine_check': {'no_such_agent': 1},
    'ui_machine_manager': {'no_such_agent': 1},
    'ui_machine_update': {'no_such_agent': 1, 'revision_unreadable': 1},
    'ui_machines': {'hub_changed': 1},
    'ui_mcp_check': {'login_as_text': 1},
    'ui_mcp_connect': {'mcp_no_endpoints': 1},
    'ui_mcp_finish': {'connect_stale': 1},
    'ui_memory': {'hub_changed': 1, 'no_such_agent': 1},
    'ui_notes': {'hub_changed': 1, 'no_such_agent': 1},
    'ui_owner_device_recovery_read': {'hub_changed': 1},
    'ui_owner_devices': {'hub_changed': 1},
    'ui_owner_enroll': {'not_owner_device': 1},
    'ui_people': {'hub_changed': 1},
    'ui_person': {'no_such_person': 1},
    'ui_person_handles': {'no_such_person': 1, 'person_handles_most': 1},
    'ui_profile_save': {'no_such_agent': 1},
    'ui_profiles': {'hub_changed': 1},
    'ui_releases': {'hub_changed': 1},
    'ui_resources': {'hub_changed': 1},
    'ui_responsibilities': {'hub_changed': 1},
    'ui_responsibility': {'hub_changed': 1},
    'ui_restore': {'command_reused': 1, 'hub_changed_sending': 1},
    'ui_roles': {'hub_changed': 1},
    'ui_secret_salts': {'hub_changed': 1},
    'ui_secret_same': {'hub_changed': 1},
    'ui_servers': {'hub_changed': 1},
    'ui_settings': {'hub_changed': 1},
    'ui_skills': {'hub_changed': 1, 'no_such_agent': 1},
    'ui_standing': {'hub_changed': 1, 'no_such_agent': 1},
    'ui_team': {'hub_changed': 1},
    'ui_trigger': {'hub_changed': 1},
    'ui_triggers': {'hub_changed': 1},
    'ui_vault': {'hub_changed': 1},
    'ui_wait': {'hub_changed': 1},
    'vendor_repo_check': {'repo_vendor': 1},
}
# The one place that writes a sentence of the table and has no code yet: a registered login that a batch of the secrets
# import refuses, which is an entry's `error` in an answer that succeeded, and no refusal of the whole command.
LEFT = {"a registered login cannot be sent as text": 1}
# The names that a call's own parameters use, which a hole cannot take
RESERVED = {"code", "names", "table", "extra", "status", "message", "self", "cls"}

NO_NAME = {"code": "hub_changed", "names": None}


def source():
    with open(os.path.join(KIT, "hub.py"), encoding="utf-8") as f:
        return ast.parse(f.read())


def sentence(node):
    """The words of a string or an f-string of the code, with {S} where a value goes, or None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else "{S}" for v in node.values)
    return None


class Calls(ast.NodeVisitor):
    """Each call in hub.py that gives a refusal its code, with the function that holds it (the outermost one, as the
    scan of the owner API's routes names it): (function, code or None, names or None, line, how). `code` None: the
    call gives a code that is not a text in the source."""

    def __init__(self):
        self.functions, self.found = [], []

    def visit_FunctionDef(self, node):
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Call(self, node):
        function, keywords = node.func, {k.arg: k.value for k in node.keywords}
        holder = self.functions[0] if self.functions else None
        if isinstance(function, ast.Name) and function.id in ("Refusal", "Conflict", "ArtifactError") \
                and "code" in keywords:
            names = keywords.get("names")
            self.add(holder, keywords["code"], None if names is None else (
                sorted(k.value for k in names.keys if isinstance(k, ast.Constant)) if isinstance(names, ast.Dict)
                and all(isinstance(k, ast.Constant) for k in names.keys) else "?"), node, "class")
            if node.args[1:] or "message" in keywords:
                self.add(holder, ast.Constant(None), None, node, "a message and a code together")
        elif isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name) \
                and function.value.id == "refusal_words" and function.attr in ("answer", "Coded") \
                or isinstance(function, ast.Name) and function.id == "Coded":
            code = node.args[0] if node.args else keywords.get("code")
            self.add(holder, code, sorted(k.arg for k in node.keywords if k.arg != "code") if not any(
                k.arg is None for k in node.keywords) else "?", node, "helper")
        self.generic_visit(node)

    def add(self, holder, code, names, node, how):
        self.found.append((holder, code.value if isinstance(code, ast.Constant) and isinstance(code.value, str)
                           else None, names, node.lineno, how))


def coded_places():
    calls = Calls()
    calls.visit(source())
    return calls.found


class Table(unittest.TestCase):
    def test_a_code_has_small_letters_digits_and_underscores(self):
        for code in WORDS:
            self.assertTrue(CODE.fullmatch(code), code)

    def test_the_table_gives_the_old_english_word_for_word(self):
        self.assertEqual(WORDS, OLD)

    def test_one_code_for_each_sentence_and_one_sentence_for_each_code(self):
        self.assertEqual(len(set(WORDS.values())), len(WORDS), "two codes for one sentence")

    def test_a_hole_is_a_plain_name_that_no_parameter_uses(self):
        for code, text in WORDS.items():
            for literal, field, spec, conversion in string.Formatter().parse(text):
                if field is None:
                    continue
                self.assertTrue(HOLE.fullmatch(field), (code, field))
                self.assertEqual((spec, conversion), ("", None), (code, field))
                self.assertNotIn(field, RESERVED, code)

    def test_holes_come_in_order_of_first_use(self):
        self.assertEqual(holes("{b} and {a} and {b}"), ("b", "a"))
        self.assertEqual(holes("no hole"), ())
        self.assertEqual(holes(WORDS["server_silent"]), ("server",))

    def test_no_code_of_the_table_is_a_code_of_the_account_words(self):
        """The account words (hub.ACCOUNT_WORDS) are a table of their own until a later slice moves them in: a code
        that both hold would mean two sentences."""
        self.assertEqual(set(WORDS) & set(hub.ACCOUNT_WORDS), set())

    def test_the_english_keeps_no_control_character_and_no_line_end(self):
        for code, text in WORDS.items():
            self.assertEqual(text, text.strip(), code)
            self.assertFalse(any(ord(c) < 32 for c in text), code)


class Names(unittest.TestCase):
    def test_the_words_hold_each_name_as_it_is_given(self):
        self.assertEqual(words("server_silent", {"server": "app-1"}),
                         "app-1 sent no reading in the last 10 minutes: check that it is on")
        self.assertEqual(words("no_such_agent"), "no such agent")
        self.assertEqual(words("agent_mid_turn", {"agent": "Customer Support"}),
                         "Customer Support is in the middle of a turn. Move it when the turn ends.")

    def test_a_name_that_is_missing_or_a_code_that_is_unknown_is_a_mistake_of_the_code(self):
        with self.assertRaises(KeyError):
            words("server_silent")
        with self.assertRaises(KeyError):
            words("not_a_code")

    def test_a_name_is_a_text_of_200_characters_at_most_or_a_whole_number(self):
        long = "x" * 300
        self.assertEqual(shown({"a": "short", "n": 3, "t": True, "none": None, "long": long}),
                         {"a": "short", "n": 3, "t": "True", "none": "None", "long": "x" * 199 + "…"})
        self.assertEqual(len(shown({"long": long})["long"]), 200)
        self.assertEqual(shown({"exact": "y" * 200}), {"exact": "y" * 200})

    def test_the_words_keep_the_whole_name_when_the_name_is_cut(self):
        long = "x" * 300
        e = hub.Refusal(409, code="server_silent", names={"server": long})
        self.assertEqual(str(e), long + " sent no reading in the last 10 minutes: check that it is on")
        self.assertEqual(refusal_body(e)["names"], {"server": "x" * 199 + "…"})

    def test_a_number_stays_a_number_in_the_answer_and_a_digit_in_the_words(self):
        with patch.dict(refusal_words.WORDS, {"a_count": "{count} of them"}):
            body = answer("a_count", count=3)
        self.assertEqual(body, {"code": "a_count", "names": {"count": 3}, "error": "3 of them"})


class Exceptions(unittest.TestCase):
    def test_a_refusal_with_names_answers_its_code_and_its_names(self):
        e = hub.Refusal(409, code="server_silent", names={"server": "app-1"})
        self.assertEqual((e.status, str(e)), (409, "app-1 sent no reading in the last 10 minutes: check that it is on"))
        self.assertEqual(refusal_body(e), {"code": "server_silent", "names": {"server": "app-1"},
                                           "error": "app-1 sent no reading in the last 10 minutes: check that it is on"})

    def test_a_refusal_with_no_name_has_no_names(self):
        e = hub.Refusal(404, code="no_such_agent")
        self.assertEqual(refusal_body(e), {"code": "no_such_agent", "error": "no such agent"})
        self.assertNotIn("names", e.extra)

    def test_a_conflict_gives_its_current_value_beside_its_code(self):
        e = hub.Conflict(code="team_changed", sha256="abc")
        self.assertIsInstance(e, hub.Refusal)
        self.assertEqual((e.status, str(e)), (409, "team.json changed meanwhile; reload it"))
        self.assertEqual(refusal_body(e), {"sha256": "abc", "code": "team_changed",
                                           "error": "team.json changed meanwhile; reload it"})

    def test_an_artifact_error_takes_a_code_and_stays_no_refusal(self):
        e = hub.ArtifactError(422, code="login_not_shown")
        self.assertNotIsInstance(e, hub.Refusal)
        self.assertEqual(refusal_body(e), {"code": "login_not_shown", "error": "registered login text cannot be displayed"})

    def test_a_refusal_with_no_code_answers_error_alone_as_before(self):
        plain = hub.Refusal(409, "the words of a place that no person meets")
        self.assertFalse(hasattr(plain, "extra"))
        self.assertEqual(refusal_body(plain), {"error": "the words of a place that no person meets"})
        self.assertEqual(refusal_body(hub.Conflict("a plain conflict", open_tasks=["T-1"])),
                         {"open_tasks": ["T-1"], "error": "a plain conflict"})
        self.assertEqual(refusal_body(hub.Conflict("a conflict with nothing")), {"error": "a conflict with nothing"})
        self.assertEqual(refusal_body(ValueError("a check")), {"error": "a check"})
        self.assertEqual(refusal_body(hub.ToolError("a tool's words")), {"error": "a tool's words"})

    def test_a_refusal_why_keeps_its_why(self):
        e = hub.refusal_why("shared", ["a", "b"])
        self.assertEqual(refusal_body(e), {"why": ["a", "b"], "error": "shared"})

    def test_a_coded_check_is_a_value_error_with_its_code_and_names(self):
        e = Coded("agent_open_signin", agent="Developer")
        self.assertIsInstance(e, ValueError)
        self.assertEqual((e.code, e.names), ("agent_open_signin", {"agent": "Developer"}))
        self.assertEqual(refusal_body(e), {
            "code": "agent_open_signin", "names": {"agent": "Developer"},
            "error": "Developer has an open sign-in. Finish it or let it run out, then try again."})
        self.assertEqual(refusal_body(Coded("no_such_task")), {"code": "no_such_task", "error": "no such task"})

    def test_a_refusal_needs_its_words_or_its_code(self):
        with self.assertRaises(KeyError):
            hub.Refusal(404)

    def test_the_account_refusal_answers_the_bytes_that_it_answered_before(self):
        """account_refusal is the same constructor now (the AI providers lane, decision D7). Its answers, with and
        without names and with an extra field, are what the old lines gave: `names` is there when it is empty."""
        def before(status, code, extra=None, **names):
            e = hub.Refusal(status, hub.ACCOUNT_WORDS[code].format(**names))
            e.extra = dict(extra or {}, code=code, names=names)
            return e
        for status, code, extra, names in (
                (409, "kind_kept", None, {}), (409, "in_use", {"agents": ["gem-1", "gem-2"]}, {}),
                (409, "mac", None, {"server": "app-1", "provider": "Gemini"}), (409, "older", None, {"server": "app-2"}),
                (400, "open", None, {"server": "app-3"}),
                (409, "change", None, {"agent": "Developer", "provider": "Claude"})):
            new, old = hub.account_refusal(status, code, extra, **names), before(status, code, extra, **names)
            self.assertEqual((new.status, str(new), new.extra), (old.status, str(old), old.extra), code)
            self.assertEqual(json.dumps(refusal_body(new)), json.dumps(refusal_body(old)), code)
            self.assertEqual(list(refusal_body(new)), list(refusal_body(old)), code)


class Places(unittest.TestCase):
    """The places of hub.py that name a code."""

    @classmethod
    def setUpClass(cls):
        cls.places = coded_places()

    def test_each_code_that_a_place_names_is_in_the_table_and_its_names_fill_the_holes_exactly(self):
        self.assertGreaterEqual(len(self.places), 135)
        for holder, code, names, line, how in self.places:
            where = f"hub.py:{line} in {holder}"
            self.assertNotEqual(how, "a message and a code together", f"{where}: the words come from the table")
            self.assertIsNotNone(code, f"{where}: a code is a text in the source, so that this test can read it")
            self.assertIn(code, WORDS, where)
            self.assertNotEqual(names, "?", f"{where}: the names are written out, one key each")
            self.assertEqual(sorted(holes(WORDS[code])), names or [], f"{where}: the names of {code}")

    def test_each_converted_place_still_has_its_code(self):
        found = {}
        for holder, code, _, _, _ in self.places:
            found.setdefault(holder, {}).setdefault(code, 0)
            found[holder][code] += 1
        lost = [f"{function}: {code} {count} (now {found.get(function, {}).get(code, 0)})"
                for function, codes in sorted(SITES.items()) for code, count in sorted(codes.items())
                if found.get(function, {}).get(code, 0) < count]
        self.assertEqual(lost, [])
        self.assertEqual(sum(sum(codes.values()) for codes in SITES.values()), 190)

    def test_the_english_of_a_sentence_of_the_table_is_written_nowhere_else_in_hub_py(self):
        """One code for each sentence: a place that writes the sentence by hand again has no code. A new place of one
        of these sentences gets its code from the table, so the sentence is in one file."""
        sentences = {re.sub(r"\{\w+\}", "{S}", text): code for code, text in WORDS.items()}
        found = {}
        for node in ast.walk(source()):
            text = sentence(node)
            if text in sentences:
                found[text] = found.get(text, 0) + 1
        self.assertEqual(found, LEFT)

    def test_each_code_of_the_table_is_named_by_a_place(self):
        """A code is added in the commit that raises it: a code that no place names says something that the hub
        never says, and the apps would carry words for it."""
        used = {code for _, code, _, _, _ in self.places}
        self.assertEqual(set(WORDS) - used, set())

    def test_each_converted_error_is_the_old_text(self):
        """For each code, the text that a place gives is the old English with its names put in."""
        for code, old in OLD.items():
            names = {name: f"<{name}>" for name in holes(old)}
            self.assertEqual(words(code, names), old.format(**names), code)
            self.assertEqual(str(hub.Refusal(409, code=code, names=names or None)), old.format(**names), code)
            self.assertEqual(answer(code, **names)["error"], old.format(**names), code)

    def test_the_plumbing_has_no_line_that_drops_the_fields_of_an_exception(self):
        with open(os.path.join(KIT, "hub.py"), encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn('{"error": str(e)}', text)
        self.assertNotIn('dict(getattr(e, "extra", {}), error=str(e))', text)


class Paths(unittest.TestCase):
    """The three ways that an exception reaches an answer: command_run, the `read` of ui_command, and a route that
    writes `self.json(e.status, refusal_body(e))`. Each carries the code and the names, and a refusal with no code
    answers `error` alone."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="fleet-refusal-paths-")
        self.addCleanup(folder.cleanup)
        own_files(self, folder.name)        # a handler of a test reads no file of the machine (test_ui_api.OwnFiles)
        self.before = hub.DB, hub.TEAM
        hub.DB = quick(sqlite3.connect(":memory:", check_same_thread=False))
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        hub.migrate()
        hub.TEAM = {"addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2"},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}
        hub.kv_set("db_id", "test-generation")
        self.addCleanup(self.restore)
        self.said = []

    def restore(self):
        hub.DB.close()
        hub.DB, hub.TEAM = self.before

    def run_command(self, act, db="test-generation"):
        return hub.command_run("tasks/T-1/control", str(uuid.uuid4()), "refusal-test", db, {"x": 1}, act)

    def handler(self, form=None):
        handler = hub.Handler.__new__(hub.Handler)
        handler.headers = {"Content-Type": "application/json", "X-Fleet-Client": "refusal-test"}
        handler.ui_allowed = lambda: True
        handler.body = lambda: b"{}"
        handler.form = lambda: dict({"request_id": str(uuid.uuid4()), "db": "test-generation"}, **(form or {}))
        handler.json = lambda code, body, headers=None: self.said.append((code, body))
        return handler

    def test_command_run_carries_the_code_and_the_names_of_a_refusal_of_the_act(self):
        def act(body):
            raise hub.Refusal(409, code="server_silent", names={"server": "app-1"})
        self.assertEqual(self.run_command(act), (409, {
            "code": "server_silent", "names": {"server": "app-1"},
            "error": "app-1 sent no reading in the last 10 minutes: check that it is on"}))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM ui_controls")["n"], 0, "a refused command leaves no record")

    def test_command_run_carries_the_current_value_of_a_conflict_with_its_code(self):
        def act(body):
            raise hub.Conflict(code="team_changed", sha256="abc")
        self.assertEqual(self.run_command(act), (409, {"sha256": "abc", "code": "team_changed",
                                                       "error": "team.json changed meanwhile; reload it"}))

    def test_command_run_answers_error_alone_for_a_refusal_with_no_code(self):
        def act(body):
            raise hub.Refusal(409, "plain words")
        self.assertEqual(self.run_command(act), (409, {"error": "plain words"}))

    def test_command_run_codes_its_own_refusals(self):
        self.assertEqual(self.run_command(lambda body: {}, db="an older generation"), (409, {
            "code": "hub_changed_sending", "error": "hub generation changed; refresh state before sending"}))

    def test_command_run_codes_the_claim_that_it_found_open(self):
        request_id = str(uuid.uuid4())
        hub.q("INSERT INTO ui_controls(request_id,route,body,client,created,result) VALUES(?,?,?,?,?,'')",
              (request_id, "tasks/T-1/control", json.dumps({"x": 1}, sort_keys=True), "refusal-test", hub.now()))
        self.assertEqual(hub.command_run("tasks/T-1/control", request_id, "refusal-test", "test-generation", {"x": 1},
                                         lambda body: {}),
                         (409, {"code": "command_interrupted", "error": WORDS["command_interrupted"]}))
        self.assertEqual(hub.command_run("tasks/T-2/control", request_id, "refusal-test", "test-generation", {"x": 1},
                                         lambda body: {}),
                         (409, {"code": "command_reused", "error": "request_id was already used for a different "
                                                                   "command"}))

    def test_the_read_of_ui_command_carries_the_code_and_the_names_of_a_coded_check(self):
        def read(data):
            raise Coded("agent_open_signin", agent="Developer")
        handler = self.handler()
        handler.ui_command("tasks/T-1/control", read, lambda body: {})
        self.assertEqual(self.said, [(400, {
            "code": "agent_open_signin", "names": {"agent": "Developer"},
            "error": "Developer has an open sign-in. Finish it or let it run out, then try again."})])

    def test_the_read_of_ui_command_carries_the_code_of_a_coded_refusal(self):
        def read(data):
            raise hub.Refusal(404, code="no_such_task")
        self.handler().ui_command("tasks/T-1/control", read, lambda body: {})
        self.assertEqual(self.said, [(404, {"code": "no_such_task", "error": "no such task"})])

    def test_the_read_of_ui_command_answers_error_alone_for_a_check_with_no_code(self):
        def read(data):
            raise ValueError("note must be text")
        self.handler().ui_command("tasks/T-1/control", read, lambda body: {})
        self.assertEqual(self.said, [(400, {"error": "note must be text"})])

    def test_a_route_that_writes_the_exception_carries_its_code_and_its_names(self):
        def act():
            raise hub.Refusal(409, code="server_no_service", names={"server": "app-2"})
        self.handler().door_route(act)
        self.assertEqual(self.said, [(409, {
            "code": "server_no_service", "names": {"server": "app-2"},
            "error": "app-2 has no server service: it did not join with a join code"})])

    def test_a_route_that_writes_the_exception_answers_error_alone_for_a_refusal_with_no_code(self):
        def act():
            raise hub.Refusal(403, "plain words")
        self.handler().door_route(act)
        self.assertEqual(self.said, [(403, {"error": "plain words"})])

    def test_the_phones_reads_carry_a_code(self):
        self.assertEqual(hub.phone_task("T-9", {"db": "test-generation"})[:2],
                         (404, {"code": "no_such_task", "error": "no such task"}))
        self.assertEqual(hub.phone_task("T-9", {"db": "an older generation"})[:2],
                         (409, {"code": "hub_changed", "error": "hub generation changed; refresh state"}))
        self.assertEqual(hub.phone_chat("nobody", {})[:2], (404, {"code": "no_such_agent", "error": "no such agent"}))
        self.assertEqual(hub.phone_ended({"db": "an older generation"})[:2],
                         (409, {"code": "hub_changed", "error": "hub generation changed; refresh state"}))


def load_tests(loader, _tests, _pattern):
    """OwnerAPI is imported, and its own tests belong to test_ui_api: this file runs the ones of its own class."""
    suite = unittest.TestSuite()
    for case in (Table, Names, Exceptions, Places, Paths):
        suite.addTests(loader.loadTestsFromTestCase(case))
    suite.addTests(OnTheHub(name) for name in OnTheHub.__dict__ if name.startswith("test_"))
    return suite


class OnTheHub(OwnerAPI):
    """The real server, so that the answer's bytes are the ones that an app reads."""

    def test_a_stale_generation_answers_its_code_and_the_english_beside_it(self):
        status, body = self.request("/ui/servers?db=an-older-generation")
        self.assertEqual((status, body), (409, {"code": "hub_changed", "error": "hub generation changed; refresh state"}))

    def test_a_command_for_a_task_that_is_not_there_answers_its_code(self):
        status, body = self.request("/ui/tasks/99/control", self.command(action="pause"))
        self.assertEqual((status, body), (404, {"code": "no_such_task", "error": "no such task"}))

    def test_a_note_of_an_agent_that_is_not_there_answers_its_code(self):
        status, body = self.request("/ui/notes/nobody?db=test-generation")
        self.assertEqual((status, body), (404, {"code": "no_such_agent", "error": "no such agent"}))


if __name__ == "__main__":
    unittest.main()

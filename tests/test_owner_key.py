"""The key of the owner's computer (hub.py, owner feature owner_key).

The hub knew the owner's computer by its address alone, and a VM or a container on that computer leaves through the
computer's own address, so the hub took such a guest for the owner. These checks hold the fix: the owner's computer
proves itself with its address AND a key, on every owner route; no route gives, replaces or removes the key for a
caller that has only the address; and a claim of the hub's own server keeps the key's SHA-256 with the owner's address.

A local hub with a test source address for each caller, the real claim listener of hubsetup.py on the loopback, and
the claim's own script with a stand-in for the listener. No real network, key, server or AI call."""
import contextlib
import hashlib
import http.server
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import hubsetup
import onboard
import owner_mcp
from leftovers import parent_pipe
from test_ui_api import OwnerAPI

MAC, STRANGER, PHONE = "127.0.0.1", "127.0.0.9", "127.0.0.5"    # the owner's computer (OwnerAPI), another, a phone
KEY, OTHER_KEY = "mac-key-" + "a" * 35, "mac-key-" + "b" * 35
HUB_IP, CODE, SHOWN = "100.64.0.9", "ABCDEFGHJKLM", "ABCD-EFGH-JKLM"
# Each owner route that is older than /ui and asks the owner's rule itself, with a body for the writes. The last one
# takes the owner's name from its path, and asked for the address alone until the review of 14 November 2026.
OLDER = (("GET", "/", None), ("GET", "/board", None), ("GET", "/board.txt", None), ("GET", "/records", None),
         ("GET", "/leakcheck", None), ("GET", "/events/owner?after=0&wait=0", None),
         ("POST", "/cases", {"case_id": "c-1", "run_id": "r-1"}), ("POST", "/evidence", {"case_id": "c-1", "kind": "k"}),
         ("POST", "/say", {"text": "an order that the owner did not give"}), ("POST", "/needs/1", {"answer": "yes"}),
         ("POST", "/secrets", {"label": "a login", "text": "Pr4ct!ce-Login#2026"}))


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Rule, Registration, Computer, Clients):  # their own cases only: OwnerAPI's are test_ui_api's
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    for cls in (Claim, ClaimScript, HubThatStarts):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


class WithKeyFolder(OwnerAPI):
    """A hub that keeps the key's file in this test's own folder, as main() keeps it beside --db."""

    def setUp(self):
        super().setUp()
        self.folder = Path(self.tmp.name) / "records"
        self.folder.mkdir(mode=0o700)
        hub.CFG["owner_key_dir"] = str(self.folder)
        hub.OWNER_REFUSALS.clear()              # each test's hub counts its own refusals, as a hub that starts
        self.addCleanup(self.forget)

    def forget(self):
        hub.CFG.pop("owner_key_dir", None)
        hub.OWNER_KEY.update(stamp=None, value=None)
        hub.OWNER_PROOF.update(value=None, expires=0.0)
        hub.OWNER_REFUSALS.clear()

    def ask(self, path="/ui/state", body=None, method=None, token=None, source=MAC, headers=None):
        """(status, the JSON object of the answer or None) of one call from `source`, with `token` as its bearer."""
        head = dict({"X-Test-Source": source}, **(headers or {}))
        if body is not None:
            head.setdefault("Content-Type", "application/json")
        if token is not None:
            head["Authorization"] = "Bearer " + token
        request = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(),
                                         method=method or ("GET" if body is None else "POST"), headers=head)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=self.patience) as answer:
                status, raw = answer.status, answer.read()
        except urllib.error.HTTPError as answer:
            with answer:
                status, raw = answer.code, answer.read()
        try:
            said = json.loads(raw)
        except ValueError:
            said = None
        return status, said if isinstance(said, dict) else None

    def count(self, table):
        return hub.q1(f"SELECT COUNT(*) n FROM {table}")["n"]


class Rule(WithKeyFolder):
    """Who the hub takes for the owner."""

    def test_a_hub_with_no_key_keeps_the_address_rule_and_refuses_a_bearer(self):
        """A fleet from before the key, until its owner's computer registers one: as every hub was. A client reads
        from key_not_expected that it must send none."""
        self.assertEqual(self.ask()[0], 200)
        status, said = self.ask(token=KEY)
        self.assertEqual((status, said["auth"]), (403, "key_not_expected"))
        self.assertEqual(self.ask(source=STRANGER)[0], 403)

    def test_a_hub_that_was_given_no_folder_holds_no_key(self):
        """A hub that a test imports as a module reads no file of the machine that the test runs on."""
        hub.CFG.pop("owner_key_dir")
        self.assertIsNone(hub.owner_key_path())
        self.assertIsNone(hub.owner_key())
        self.assertEqual(self.ask()[0], 200)

    def test_with_a_key_the_address_alone_is_refused_on_every_ui_route(self):
        """The hole itself: a VM or a container on the owner's computer has that computer's address and no key."""
        hub.keep_owner_key(sha(KEY))
        for path in ("/ui/state", "/ui/team", "/ui/machines?db=test-generation", "/ui/owner/devices",
                     "/ui/knowledge", "/ui/wait?db=test-generation"):
            status, said = self.ask(path)
            self.assertEqual((status, said and said.get("auth")), (403, "owner_key_required"), path)
        status, said = self.ask("/ui/messages", dict(self.command(), recipient="manager", text="An order."))
        self.assertEqual((status, said["auth"]), (403, "owner_key_required"))
        self.assertEqual(self.count("events"), 0)
        self.assertEqual(self.count("ui_requests"), 0)

    def test_with_a_key_the_owner_s_computer_is_the_owner(self):
        hub.keep_owner_key(sha(KEY))
        status, said = self.ask(token=KEY)
        self.assertEqual(status, 200)
        self.assertIn("owner_key", said["ui_features"])
        status, said = self.ask("/ui/messages", dict(self.command(), recipient="manager", text="An order."), token=KEY,
                                headers={"X-Fleet-Client": "founderizer-swift/1/test"})
        self.assertEqual(status, 200, said)

    def test_a_wrong_key_is_refused_and_never_taken_as_absent(self):
        hub.keep_owner_key(sha(KEY))
        for token in (OTHER_KEY, "", KEY + "x", KEY[:-1]):
            status, said = self.ask(token=token)
            self.assertEqual((status, said["auth"]), (403, "owner_key_mismatch"), repr(token))

    def test_the_key_from_another_address_is_refused(self):
        """Address AND key: the key alone is no owner."""
        hub.keep_owner_key(sha(KEY))
        status, said = self.ask(token=KEY, source=STRANGER)
        self.assertEqual(status, 403)
        self.assertNotIn("auth", said)

    def test_the_older_owner_routes_ask_for_the_key_too(self):
        """The board, the records and the five writes beside them asked for the address alone: a guest read every
        record there and wrote to the manager as the owner. The leak check asked nobody at all: each agent's shell
        could start its scan of every table, and read from its answer which rows hold a login."""
        hub.keep_owner_key(sha(KEY))
        before = {table: self.count(table) for table in ("events", "cases", "evidence")}
        for method, path, body in OLDER:
            status, said = self.ask(path, body, method=method)
            self.assertEqual((status, said and said.get("auth")), (403, "owner_key_required"), f"{method} {path}")
            status, said = self.ask(path, body, method=method, token=OTHER_KEY)
            self.assertEqual((status, said and said.get("auth")), (403, "owner_key_mismatch"), f"{method} {path}")
        for table in ("events", "cases", "evidence"):
            self.assertEqual(self.count(table), before[table], table)
        for path in ("/", "/board", "/board.txt", "/records", "/leakcheck", "/events/owner?after=0&wait=0"):
            self.assertEqual(self.ask(path, token=KEY)[0], 200, path)
        self.assertEqual(self.ask("/leakcheck", token=KEY, source=STRANGER)[0], 403)        # an agent's machine
        self.assertEqual(self.ask("/leakcheck", token=KEY)[1], {"hits": []})
        self.assertIsNone(hub.q1("SELECT 1 FROM agents WHERE name='owner' AND alive='guest'"))

    def test_a_guest_cannot_read_or_mark_the_owner_s_events(self):
        """GET /events/owner takes the owner's name from its path. It gave each Needs-you title to the address alone,
        and its `alive` wrote a row."""
        hub.keep_owner_key(sha(KEY))
        status, said = self.ask("/events/owner?after=0&wait=0&alive=guest")
        self.assertEqual((status, said.get("auth"), sorted(said)), (403, "owner_key_required", ["auth", "error"]))
        self.assertIsNone(hub.q1("SELECT 1 FROM agents WHERE name='owner'"))

    def test_the_key_is_asked_inside_the_one_owner_rule(self):
        """The key is asked in Handler.allowed itself, for the name "owner" however a route came by that name. The
        address alone is taken in one place: the route that registers a key."""
        source = Path(hub.__file__).read_text(encoding="utf-8")
        self.assertEqual(source.count("address_only=True"), 1)
        rule = source[source.index("    def allowed(self, who, broker=False, address_only=False):"):
                      source.index("    def works_for(self, agent):")]
        self.assertIn('        if who == "owner":\n            return True if address_only else self.owner_key_allowed()', rule)
        route = source[source.index("    def ui_owner_key(self):"):source.index("    def device_allowed(self, device):")]
        self.assertIn('self.allowed("owner", address_only=True)', route)

    def test_a_head_request_asks_for_the_key_too(self):
        hub.keep_owner_key(sha(KEY))
        for path in ("/ui/state", "/board.txt", "/records"):
            self.assertEqual(self.ask(path, method="HEAD")[0], 403, path)
            self.assertEqual(self.ask(path, method="HEAD", token=KEY)[0], 200, path)

    def test_every_write_route_asks_for_the_key_and_not_only_messages(self):
        """A sample of the owner's commands, each with its own route. (test_access_refusals has every route of the
        owner API's contract, which the published tests cannot read.)"""
        hub.keep_owner_key(sha(KEY))
        for path in ("/ui/needs/1", "/ui/team/agents/manager", "/ui/owner/devices/code", "/ui/team/reload",
                     "/ui/attachments", "/ui/releases/auto", "/ui/knowledge", "/ui/settings"):
            status, said = self.ask(path, self.command())
            self.assertEqual((status, said and said.get("auth")), (403, "owner_key_required"), path)
        self.assertEqual(self.count("ui_requests"), 0)

    def test_the_sha_of_the_key_is_no_key(self):
        """The hub keeps the SHA-256 in a file, and a call that brings the SHA-256 itself is refused: whoever reads
        that file on the hub's server has no key."""
        hub.keep_owner_key(sha(KEY))
        self.assertEqual(self.ask(token=sha(KEY))[1]["auth"], "owner_key_mismatch")

    def test_a_refusal_never_says_the_key_or_its_sha(self):
        hub.keep_owner_key(sha(KEY))
        self.ask(token=OTHER_KEY)
        self.ask()
        said = " ".join(r["what"] for r in hub.q("SELECT what FROM log"))
        for secret in (KEY, OTHER_KEY, sha(KEY), sha(OTHER_KEY)):
            self.assertNotIn(secret, said)
        self.assertIn("owner_key_mismatch", said)

    def test_a_key_file_that_cannot_be_read_opens_nothing(self):
        """A damaged file never gives the owner's routes back to the address alone."""
        path = self.folder / hub.OWNER_KEY_FILE
        for text in ("", "not json", "[]", '{"sha256": 7}', '{"sha256": "' + "g" * 64 + '"}', '{"since": 1}'):
            path.write_text(text, encoding="utf-8")
            hub.OWNER_KEY.update(stamp=None, value=None)
            self.assertEqual(self.ask()[0:1], (403,), text)
            self.assertEqual(self.ask(token=KEY)[1]["auth"], "owner_key_mismatch", text)
            self.assertEqual(self.ask(token="")[1]["auth"], "owner_key_mismatch", text)

    def test_what_stands_in_place_of_the_key_file_and_is_no_file_opens_nothing(self):
        """A folder, a file that this user cannot read, and a link whose file is gone: each is a key file that is
        damaged, never "no key"."""
        path = self.folder / hub.OWNER_KEY_FILE
        path.mkdir()
        self.assertEqual(self.ask()[0], 403)
        self.assertEqual(self.ask(token=KEY)[1]["auth"], "owner_key_mismatch")
        path.rmdir()
        path.symlink_to(self.folder / "a-file-that-is-gone")
        hub.OWNER_KEY.update(stamp=None, value=None)
        self.assertEqual(self.ask()[0], 403)
        path.unlink()
        if os.geteuid() != 0:
            path.write_text(json.dumps({"sha256": sha(KEY), "since": 1}))
            path.chmod(0)
            hub.OWNER_KEY.update(stamp=None, value=None)
            self.assertEqual(self.ask()[0], 403)
            self.assertEqual(self.ask(token=KEY)[1]["auth"], "owner_key_mismatch")
            path.chmod(0o600)
        path.unlink()
        self.assertEqual(self.ask()[0], 200)        # nothing at all at the path: no key was registered

    def test_a_key_file_whose_state_cannot_be_read_opens_nothing(self):
        """A link to itself: the system cannot say what is there (no "not found", another error). It is a key file
        that is damaged, never "no key"."""
        path = self.folder / hub.OWNER_KEY_FILE
        path.symlink_to(path)
        with self.assertRaises(OSError) as fault:
            os.stat(path)
        self.assertNotIsInstance(fault.exception, FileNotFoundError)
        self.assertEqual(hub.owner_key(), hub.OWNER_KEY_BROKEN)
        self.assertEqual(self.ask()[1]["auth"], "owner_key_required")
        self.assertEqual(self.ask(token=KEY)[1]["auth"], "owner_key_mismatch")
        path.unlink()
        self.assertEqual(self.ask()[0], 200)

    def test_a_key_file_that_goes_while_the_hub_runs_is_said_once(self):
        """The hub goes back to the address rule then, which is the hole that the key closes: its own output says so,
        as the line of a start with no key does."""
        hub.keep_owner_key(sha(KEY))
        self.assertEqual(self.ask(token=KEY)[0], 200)
        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            (self.folder / hub.OWNER_KEY_FILE).unlink()
            self.assertEqual(self.ask()[0], 200)
            self.assertEqual(self.ask()[0], 200)
            self.assertEqual(self.ask(token=KEY)[1]["auth"], "key_not_expected")
        self.assertEqual(said.getvalue().count("The file of the key of the owner's computer is gone"), 1)
        self.assertIn("sh hub.sh --reclaim", said.getvalue())
        for secret in (KEY, sha(KEY)):
            self.assertNotIn(secret, said.getvalue())

    def test_a_key_that_was_registered_and_goes_before_the_next_call_is_said_too(self):
        hub.keep_owner_key(sha(KEY))
        said = io.StringIO()
        with contextlib.redirect_stdout(said):
            (self.folder / hub.OWNER_KEY_FILE).unlink()
            self.assertEqual(self.ask()[0], 200)
            self.assertEqual(self.ask()[0], 200)
        self.assertEqual(said.getvalue().count("The file of the key of the owner's computer is gone"), 1)

    def test_a_program_that_asks_again_and_again_fills_no_log(self):
        """A program from before the key that is left open asks every few seconds, and so does a guest that tries: a
        row for the first refused call of an address, then for each tenth up to the hundredth, then for each
        hundredth. Never one for each call, and never a long silence."""
        hub.keep_owner_key(sha(KEY))

        def rows(code):
            return [r["what"] for r in hub.q("SELECT what FROM log WHERE what LIKE ? ORDER BY id", (f"REFUSED %{code}",))]
        for _ in range(25):
            self.assertEqual(self.ask()[1]["auth"], "owner_key_required")       # each call is still refused
        self.assertEqual(len(rows("owner_key_required")), 3)
        self.assertIn("REFUSED a call for owner from 127.0.0.1", rows("owner_key_required")[0])
        self.assertIn("REFUSED 10 calls for owner from 127.0.0.1", rows("owner_key_required")[1])
        self.assertIn("REFUSED 20 calls for owner from 127.0.0.1", rows("owner_key_required")[2])
        for _ in range(3):
            self.assertEqual(self.ask(token=OTHER_KEY)[1]["auth"], "owner_key_mismatch")
        self.assertEqual(len(rows("owner_key_mismatch")), 1)                    # counted for each kind of refusal
        self.assertEqual(self.ask(token=KEY)[0], 200)
        # The schedule, with no hub: 1, each tenth to 100, then each hundredth.
        hub.OWNER_REFUSALS[("owner_key_required", "127.0.0.1")] = 98
        for _ in range(103):
            self.ask()
        said = " ".join(rows("owner_key_required")[3:])
        for count in (100, 200):
            self.assertIn(f"REFUSED {count} calls", said)
        for count in (99, 101, 110, 150, 190, 201):
            self.assertNotIn(f"REFUSED {count} calls", said)

    def test_the_other_refusals_of_the_address_alone_are_counted_too(self):
        """A wrong one-time value, and a key for a hub that expects none: a caller with the owner's address alone can
        bring each of them about as often as it likes."""
        def rows(code):
            return hub.q1("SELECT COUNT(*) n FROM log WHERE what LIKE ?", (f"REFUSED %{code}",))["n"]
        for _ in range(12):
            self.assertEqual(self.ask(token=KEY)[1]["auth"], "key_not_expected")
            self.assertEqual(self.ask("/ui/owner/key", {"sha256": sha(KEY), "proof": "x" * 43})[1]["auth"],
                             "owner_proof_mismatch")
        self.assertEqual((rows("key_not_expected"), rows("owner_proof_mismatch")), (2, 2))

    def test_the_file_is_read_again_when_it_changes(self):
        """The claim writes the file while the hub is stopped, and a second claim replaces it: the hub takes the file
        as it is, and a file that goes takes the key with it."""
        path = self.folder / hub.OWNER_KEY_FILE
        hub.keep_owner_key(sha(KEY))
        self.assertEqual(self.ask(token=KEY)[0], 200)
        with patch.object(hubsetup, "say", lambda _words: None):
            hubsetup.keep_owner_key(str(self.folder / "pilot.db"), sha(OTHER_KEY))
        self.assertEqual(self.ask(token=KEY)[1]["auth"], "owner_key_mismatch")
        self.assertEqual(self.ask(token=OTHER_KEY)[0], 200)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        path.unlink()
        with contextlib.redirect_stdout(io.StringIO()):         # the hub says that the file is gone (the test above)
            self.assertEqual(self.ask()[0], 200)

    def test_an_owner_device_keeps_its_own_rule(self):
        """A phone has its own address and its own key: the key of the owner's computer changes nothing for it, and is
        no key of the phone."""
        hub.TEAM["owner_devices"] = {"iphone": {"label": "iPhone", "address": PHONE}}
        hub.q("INSERT INTO owner_devices(device,sha256,created,last_seen,kind) VALUES('iphone',?,?,NULL,'iphone')",
              (sha("phone-key"), hub.now()))
        hub.keep_owner_key(sha(KEY))
        self.assertEqual(self.ask("/ui/mobile", token="phone-key", source=PHONE)[0], 200)
        self.assertEqual(self.ask("/ui/mobile", token=KEY, source=PHONE)[1]["auth"], "device_key_mismatch")
        self.assertEqual(self.ask("/ui/mobile", token="phone-key")[1]["auth"], "owner_key_mismatch")


class Registration(WithKeyFolder):
    """POST /ui/owner/key: how the owner's computer registers its key on a hub that runs."""

    def proof(self):
        status, said = self.ask("/ui/owner/key", {})
        self.assertEqual((status, said["registered"]), (200, False))
        return said["proof_file"]

    def test_the_address_alone_gets_a_file_s_path_and_no_key(self):
        """The first call writes a one-time value where only the hub's own user and root read it. A guest behind the
        owner's computer gets the path, which it cannot read."""
        path = self.proof()
        self.assertEqual(path, os.path.realpath(self.folder / hub.OWNER_PROOF_FILE))     # no link in it
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        value = Path(path).read_text(encoding="utf-8").strip()
        self.assertRegex(value, r"^[A-Za-z0-9_-]{43}$")
        self.assertIsNone(hub.owner_key())
        self.assertEqual(self.ask()[0], 200)        # nothing changed for the owner's routes
        said = json.dumps(self.ask("/ui/owner/key", {})[1])
        self.assertNotIn(value, said)

    def test_the_value_of_the_file_registers_the_key(self):
        value = Path(self.proof()).read_text(encoding="utf-8").strip()
        status, said = self.ask("/ui/owner/key", {"sha256": sha(KEY), "proof": value})
        self.assertEqual((status, said["registered"]), (200, True))
        self.assertEqual(hub.owner_key()["sha256"], sha(KEY))
        self.assertEqual(hub.owner_key()["since"], said["since"])
        self.assertEqual(stat.S_IMODE((self.folder / hub.OWNER_KEY_FILE).stat().st_mode), 0o600)
        self.assertFalse((self.folder / hub.OWNER_PROOF_FILE).exists())
        self.assertEqual(self.ask()[1]["auth"], "owner_key_required")
        self.assertEqual(self.ask(token=KEY)[0], 200)

    def test_a_wrong_or_an_old_value_registers_nothing(self):
        value = Path(self.proof()).read_text(encoding="utf-8").strip()
        for wrong in ("", "x" * 43, value[:-1], value + "x", 7, ["a"], None):
            body = {"sha256": sha(KEY), "proof": wrong}
            status, said = self.ask("/ui/owner/key", body)
            if wrong is None:
                self.assertEqual(status, 400, said)         # sha256 with no proof: the address registers nothing
            else:
                self.assertEqual((status, said["auth"]), (403, "owner_proof_mismatch"), repr(wrong))
        hub.OWNER_PROOF["expires"] = hub.now() - 1
        status, said = self.ask("/ui/owner/key", {"sha256": sha(KEY), "proof": value})
        self.assertEqual((status, said["auth"]), (403, "owner_proof_mismatch"))
        self.assertIsNone(hub.owner_key())

    def test_two_calls_with_one_value_at_the_same_time_register_one_key(self):
        value = Path(self.proof()).read_text(encoding="utf-8").strip()
        answers, go = [], threading.Barrier(2)

        def call(key):
            go.wait(5)
            answers.append((self.ask("/ui/owner/key", {"sha256": sha(key), "proof": value})[0], key))
        threads = [threading.Thread(target=call, args=(key,)) for key in (KEY, OTHER_KEY)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(15)
        self.assertEqual(sorted(code for code, _ in answers), [200, 403])
        self.assertEqual(hub.owner_key()["sha256"], sha(next(key for code, key in answers if code == 200)))

    def test_the_compare_ends_the_value_in_the_same_step(self):
        """Not after the key is kept: a second call that brings the value while the first one still writes the key
        finds no value. The first call is held between its compare and its write here."""
        value = Path(self.proof()).read_text(encoding="utf-8").strip()
        inside, go, answers = threading.Event(), threading.Event(), {}
        real = hub.keep_owner_key

        def held(digest):
            inside.set()
            go.wait(10)
            return real(digest)

        def first():
            answers["first"] = self.ask("/ui/owner/key", {"sha256": sha(KEY), "proof": value})[0]
        with patch.object(hub, "keep_owner_key", held):
            thread = threading.Thread(target=first, daemon=True)
            thread.start()
            self.assertTrue(inside.wait(10))
            status, said = self.ask("/ui/owner/key", {"sha256": sha(OTHER_KEY), "proof": value})
            self.assertEqual((status, said["auth"]), (403, "owner_proof_mismatch"))
            go.set()
            thread.join(10)
        self.assertEqual(answers, {"first": 200})
        self.assertEqual(hub.owner_key()["sha256"], sha(KEY))
        # And the function by itself: the value is taken once.
        value = Path(self.proof()).read_text(encoding="utf-8").strip()
        self.assertFalse(hub.owner_proof_taken(value + "x"))
        self.assertTrue(hub.owner_proof_taken(value))
        self.assertFalse(hub.owner_proof_taken(value))
        self.assertFalse((self.folder / hub.OWNER_PROOF_FILE).exists())

    def test_the_value_ends_after_ten_minutes(self):
        value = Path(self.proof()).read_text(encoding="utf-8").strip()
        self.assertEqual(hub.OWNER_PROOF_LIFE, 600)
        real = hub.now
        with patch.object(hub, "now", lambda: real() + hub.OWNER_PROOF_LIFE - 5):
            first = Path(self.proof()).read_text(encoding="utf-8").strip()      # still the open value
        self.assertEqual(first, value)
        with patch.object(hub, "now", lambda: real() + hub.OWNER_PROOF_LIFE + 1):
            status, said = self.ask("/ui/owner/key", {"sha256": sha(KEY), "proof": value})
            self.assertEqual((status, said["auth"]), (403, "owner_proof_mismatch"))
            self.assertNotEqual(Path(self.proof()).read_text(encoding="utf-8").strip(), value)     # a new one
        self.assertIsNone(hub.owner_key())

    def test_asking_again_does_not_write_the_file_again(self):
        """A caller with the address alone can ask as often as it likes: the hub writes the file once for each value,
        and again only when the file is not as the hub left it."""
        path = Path(self.proof())
        first = (path.stat().st_ino, path.stat().st_mtime_ns)
        for _ in range(5):
            self.proof()
        self.assertEqual((path.stat().st_ino, path.stat().st_mtime_ns), first)
        value = path.read_text()
        path.unlink()
        self.assertEqual(Path(self.proof()).read_text(), value)         # a file that is gone comes back
        path.chmod(0o644)
        self.proof()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)      # and one whose mode changed is put right

    def test_a_second_asker_does_not_take_the_value_away(self):
        """A guest that asks again and again cannot stop the owner's computer: the open value stays as it is."""
        first = Path(self.proof()).read_text(encoding="utf-8")
        for _ in range(3):
            self.assertEqual(Path(self.proof()).read_text(encoding="utf-8"), first)
        self.assertEqual(self.ask("/ui/owner/key", {"sha256": sha(KEY), "proof": first.strip()})[0], 200)
        self.assertNotEqual(Path(self.proof()).read_text(encoding="utf-8"), first)

    def test_a_computer_that_lost_its_key_registers_a_new_one_the_same_way(self):
        """With a key registered, the address alone still gets only the path: the new key needs the file's value."""
        hub.keep_owner_key(sha(KEY))
        status, said = self.ask("/ui/owner/key", {"sha256": sha(OTHER_KEY)})
        self.assertEqual(status, 400)
        self.assertEqual(hub.owner_key()["sha256"], sha(KEY))
        value = Path(self.proof()).read_text(encoding="utf-8").strip()
        self.assertEqual(hub.owner_key()["sha256"], sha(KEY))
        self.assertEqual(self.ask("/ui/owner/key", {"sha256": sha(OTHER_KEY), "proof": value})[0], 200)
        self.assertEqual(self.ask(token=KEY)[1]["auth"], "owner_key_mismatch")
        self.assertEqual(self.ask(token=OTHER_KEY)[0], 200)

    def test_only_the_owner_s_address_may_ask(self):
        for source in (STRANGER, "127.0.0.2"):          # another machine, and the hub's own
            self.assertEqual(self.ask("/ui/owner/key", {}, source=source)[0], 403, source)
        self.assertFalse((self.folder / hub.OWNER_PROOF_FILE).exists())
        hub.TEAM["owner_devices"] = {"iphone": {"label": "iPhone", "address": PHONE}}
        self.assertEqual(self.ask("/ui/owner/key", {}, source=PHONE)[0], 403)
        self.assertEqual(self.ask("/ui/owner/key", {}, headers={"Origin": self.base})[0], 403)
        self.assertFalse((self.folder / hub.OWNER_PROOF_FILE).exists())

    def test_what_the_route_refuses(self):
        value = Path(self.proof()).read_text(encoding="utf-8").strip()
        for body in ({"proof": value}, {"proof": value, "sha256": "A" * 64}, {"proof": value, "sha256": "a" * 63},
                     {"proof": value, "sha256": 7}, {"proof": value, "sha256": sha(KEY), "key": KEY}):
            self.assertEqual(self.ask("/ui/owner/key", body)[0], 400, body)
        self.assertEqual(self.ask("/ui/owner/key", {}, headers={"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.ask("/ui/owner/key", {"proof": "x" * 5000})[0], 413)
        self.assertIsNone(hub.owner_key())
        self.assertEqual(self.ask("/ui/owner/key", {"sha256": sha(KEY), "proof": value})[0], 200)   # no try was used up
        hub.CFG.pop("owner_key_dir")
        self.assertEqual(self.ask("/ui/owner/key", {})[0], 409)

    def test_the_log_says_that_a_key_came_and_never_which(self):
        value = Path(self.proof()).read_text(encoding="utf-8").strip()
        self.ask("/ui/owner/key", {"sha256": sha(KEY), "proof": "x" * 43})
        self.ask("/ui/owner/key", {"sha256": sha(KEY), "proof": value})
        said = " ".join(r["what"] for r in hub.q("SELECT what FROM log"))
        self.assertIn("registered its key", said)
        self.assertIn("owner_proof_mismatch", said)
        for secret in (value, sha(KEY), KEY):
            self.assertNotIn(secret, said)


class Computer(WithKeyFolder):
    """POST /ui/owner/computer, and owner_computer of GET /ui/state and GET /ui/mobile (owner feature owner_computer,
    owner API 1.273): whether the owner's computer is a Mac or a PC, and what its app can do."""

    # The names that the PC app sends, as UI-API.md 1.273 gives them: the default is a Mac with all of them.
    MAC = {"kind": "mac", "label": "Mac", "can": ["run", "takeover", "door", "agents", "servers", "secrets", "apps",
                                                  "people", "channels", "knowledge", "backup", "devices"]}
    PC = {"kind": "windows", "can": ["run", "agents"]}

    def said(self, token=KEY):
        """owner_computer of GET /ui/state, which GET /ui/mobile must give the same."""
        (state, whole), (mobile, phone) = self.ask(token=token), self.ask("/ui/mobile", token=token)
        self.assertEqual((state, mobile), (200, 200))
        self.assertEqual(whole["owner_computer"], phone["owner_computer"])
        return whole["owner_computer"]

    def file(self):
        return (self.folder / hub.OWNER_KEY_FILE).read_bytes()

    def test_only_the_owner_s_computer_with_its_key_says_what_it_is(self):
        """A VM or a container on the owner's computer has its address and not its key, and a phone is a device. A
        route that took the address alone, as POST /ui/owner/key does (address_only), would let a guest say that the
        owner has a PC that can do nothing, and the agents would stop asking him for what his Mac does. The refused
        calls leave the key's file as it was, byte for byte. The owner's own call keeps the key and its time in the
        file: a write that lost the SHA-256 would make the file damaged and refuse the owner on every route."""
        hub.TEAM["owner_devices"] = {"iphone": {"label": "iPhone", "address": PHONE}}
        hub.q("INSERT INTO owner_devices(device,sha256,created,last_seen,kind) VALUES('iphone',?,?,NULL,'iphone')",
              (sha("phone-key"), hub.now()))
        hub.keep_owner_key(sha(KEY))
        before = self.file()
        for token, source, auth in ((None, MAC, "owner_key_required"), (OTHER_KEY, MAC, "owner_key_mismatch"),
                                    ("phone-key", PHONE, "device_not_allowed"), (KEY, STRANGER, None)):
            status, said = self.ask("/ui/owner/computer", self.PC, token=token, source=source)
            self.assertEqual((status, said.get("auth")), (403, auth), source)
        self.assertEqual(self.file(), before)
        self.assertEqual(self.said(), self.MAC)
        status, said = self.ask("/ui/owner/computer", self.PC, token=KEY)
        pc = {"kind": "windows", "label": "PC", "can": ["run", "agents"]}
        self.assertEqual((status, said), (200, {"owner_computer": pc, "changed": True}))
        self.assertEqual(self.said(), pc)
        self.assertEqual({k: v for k, v in json.loads(self.file()).items() if k in ("sha256", "since")},
                         json.loads(before))

    def test_a_hub_with_no_kind_answers_as_for_a_mac(self):
        """A Mac fleet: its app never sends the call, so its hub has no key file (a fleet from before the key), or a
        file with no kind. Both read as a Mac that can do every name, and so does a kind that this hub does not know.
        A default of no names, or of a PC, would tell every Mac fleet's agents that the owner can do nothing; a name
        that the hub renames alone would drop the PC app's name with no error. A read writes nothing."""
        self.assertEqual(self.said(token=None), self.MAC)                 # no key file
        hub.keep_owner_key(sha(KEY))
        before = self.file()
        self.assertEqual(self.said(), self.MAC)                           # a file with no kind
        self.assertEqual(self.file(), before)
        path = self.folder / hub.OWNER_KEY_FILE
        path.write_text(json.dumps(dict(json.loads(before), kind="linux", can=["run"])))
        self.assertEqual(self.said(), self.MAC)                           # a kind of a later hub
        hub.CFG.pop("owner_key_dir")
        self.assertEqual(self.said(token=None), self.MAC)                 # a hub with no folder for a key

    def test_a_new_key_starts_again_from_the_default(self):
        """What a PC said belongs to its key. A registration of a new key and a claim write the file anew, and the
        kind starts again from the default: a hub that carried it over would keep a PC's limits for a Mac that took
        its place."""
        hub.keep_owner_key(sha(KEY))
        self.assertEqual(self.ask("/ui/owner/computer", self.PC, token=KEY)[0], 200)
        self.assertEqual(self.said()["kind"], "windows")
        hub.keep_owner_key(sha(OTHER_KEY))                                # POST /ui/owner/key
        self.assertEqual(self.said(token=OTHER_KEY), self.MAC)
        self.assertEqual(self.ask("/ui/owner/computer", self.PC, token=OTHER_KEY)[0], 200)
        with patch.object(hubsetup, "say", lambda _words: None):         # a second claim
            hubsetup.keep_owner_key(str(self.folder / "pilot.db"), sha(KEY))
        self.assertEqual(self.said(), self.MAC)

    def test_what_the_route_refuses_drops_and_writes_once(self):
        """A refused body writes nothing; a name that the hub does not know is dropped, so a later version never
        reads it as a page that the PC has; and a body that says what the hub holds writes nothing, whatever the
        order of its names, since the PC app sends it at each start and at each change of `db`. A hub with no key
        keeps the default and writes no file."""
        self.assertEqual(self.ask("/ui/owner/computer", self.PC)[0], 409)
        self.assertFalse((self.folder / hub.OWNER_KEY_FILE).exists())
        hub.keep_owner_key(sha(KEY))
        before = self.file()
        for body in ({"kind": "linux", "can": []}, {"kind": "Windows", "can": []}, {"kind": ["windows"], "can": []},
                     {"can": ["run"]}, {"kind": "windows"}, {"kind": "windows", "can": "run"},
                     {"kind": "windows", "can": [], "db": "test-generation"}):
            self.assertEqual(self.ask("/ui/owner/computer", body, token=KEY)[0], 400, body)
        self.assertEqual(self.ask("/ui/owner/computer", self.PC, token=KEY,
                                  headers={"Content-Type": "text/plain"})[0], 415)
        state = hub.change_token().split(".")[1]           # the part of the token that wakes GET /ui/wait
        status, said = self.ask("/ui/owner/computer", {"kind": "mac", "can": self.MAC["can"]}, token=KEY)
        self.assertEqual((status, said["changed"]), (200, False))         # the default, as the file says it
        self.assertEqual(self.file(), before)
        self.assertEqual(hub.change_token().split(".")[1], state)
        body = {"kind": "windows", "can": ["agents", "fly", 7, None, {"run": 1}, "run", "agents"]}
        status, said = self.ask("/ui/owner/computer", body, token=KEY)
        self.assertEqual((status, said["owner_computer"]["can"], said["changed"]), (200, ["run", "agents"], True))
        self.assertNotEqual(hub.change_token().split(".")[1], state, "a change wakes the apps' GET /ui/wait")
        state, written = hub.change_token().split(".")[1], (self.folder / hub.OWNER_KEY_FILE).stat()
        status, said = self.ask("/ui/owner/computer", {"kind": "windows", "can": ["agents", "run"]}, token=KEY)
        self.assertEqual((status, said["changed"]), (200, False))
        self.assertEqual(hub.change_token().split(".")[1], state, "a write of nothing wakes no app")
        now = (self.folder / hub.OWNER_KEY_FILE).stat()
        self.assertEqual((now.st_ino, now.st_mtime_ns), (written.st_ino, written.st_mtime_ns))
        self.assertEqual(sum("owner's computer says" in r["what"] for r in hub.q("SELECT what FROM log")), 1)

    def test_a_change_during_a_read_is_in_that_read(self):
        """An app reads owner_computer, then waits on GET /ui/wait with the token of that answer. A read that took
        the kind before its moment could hold the old kind beside a token that already counts the change: the app's
        wait would never wake for it, and a PC would stay a Mac on that app. Here the write and its changed() come
        just before the moment of each read, as a call of the PC can between the two."""
        hub.keep_owner_key(sha(KEY))
        real, pending = hub.state_moment, []

        @contextlib.contextmanager
        def late():
            if pending:                 # once for each read: a moment inside the read's own moment is that moment
                self.assertIs(hub.keep_owner_computer(sha(KEY), "windows", pending.pop()), True)
                hub.changed()
            with real() as moment:
                yield moment
        with patch.object(hub, "state_moment", late):
            pending.append(("run",))
            whole = self.ask(token=KEY)[1]
            pending.append(("agents",))
            phone = self.ask("/ui/mobile", token=KEY)[1]
        self.assertEqual(whole["owner_computer"], {"kind": "windows", "label": "PC", "can": ["run"]})
        self.assertEqual(phone["owner_computer"], {"kind": "windows", "label": "PC", "can": ["agents"]})


class Clients(WithKeyFolder):
    """The owner's own programs on that computer send its key: owner_mcp.py, the kit's onboard.py and fleet.py's owner
    commands. Each reads the same file, `<host>_<port>` in ~/.founderizer/owner-keys, at each call. (The test fleet's
    own caller has the same checks in test_owner_key_rig.py, which is not published.)"""

    def setUp(self):
        super().setUp()
        self.home = Path(self.tmp.name) / "home"
        (self.home / ".founderizer").mkdir(parents=True)
        for one in (patch.object(owner_mcp, "HOME", self.home / ".founderizer"),
                    patch.object(owner_mcp, "HUB_FILE", self.home / ".founderizer" / "hub"),
                    patch.object(owner_mcp, "CLIENT_FILE", self.home / ".founderizer" / "client"),
                    patch.dict(os.environ, {"HOME": str(self.home)})):
            one.start()
            self.addCleanup(one.stop)
        self.file = self.home / ".founderizer" / "owner-keys" / ("127.0.0.1_" + self.base.rsplit(":", 1)[1])

    def keep(self, key):
        self.file.parent.mkdir(mode=0o700, exist_ok=True)
        self.file.write_text(key + "\n", encoding="utf-8")

    def test_every_program_gives_the_file_the_same_name(self):
        """And it is the name that the app gives it (OwnerMacKey.place in the app's tests, with these addresses): the
        hub's number and its port. A name of the hub has the file of the number that the lookup gives it, and a name
        that has no number now has no file and no key."""
        numbers = {"hub.example.com": "100.64.0.9", "hub.example": "FD7A:115C:A1E0::1"}

        def lookup(host):
            return numbers.get(host)

        def every_address(host, *_more, **_named):         # the system's own lookup, for the owner's commands
            if host not in numbers:
                raise socket.gaierror("no such name")
            six = ":" in numbers[host]
            return [(socket.AF_INET6 if six else socket.AF_INET, socket.SOCK_STREAM, 6, "", (numbers[host], 0))]
        folder = self.home / ".founderizer" / "owner-keys"
        for base, name in (("http://100.64.0.9:8765", "100.64.0.9_8765"), ("http://100.64.0.9:8765/", "100.64.0.9_8765"),
                           ("http://Hub.Example.COM:9000/ui/state?db=1", "100.64.0.9_9000"),
                           ("http://hub.example", "fd7a-115c-a1e0--1_80"), ("https://hub.example", "fd7a-115c-a1e0--1_443"),
                           ("http://[fd7a:115c:a1e0::1]:8765", "fd7a-115c-a1e0--1_8765")):
            self.assertEqual(owner_mcp.owner_key_file(base, lookup), folder / name, base)
            folder.mkdir(mode=0o700, exist_ok=True)
            (folder / name).write_text(KEY + "\n")
            self.assertEqual(owner_mcp.owner_key(base, lookup=lookup), KEY, base)
            self.assertEqual(onboard.owner_computer_key(base, lookup=lookup), KEY, base)
            with patch.object(fleet, "HUB", base.split("/ui/")[0].rstrip("/")), \
                    patch.object(socket, "getaddrinfo", every_address):
                self.assertEqual(fleet.owner_computer_key(), KEY, base)
            (folder / name).unlink()
        self.assertEqual(owner_mcp.owner_key_file("100.64.0.9:8765").name, "100.64.0.9_8765")
        # A name with no number now, and a lookup that gives what is no address: no file, and no key under the
        # name as it is written either (no program writes such a file).
        (folder / "unknown.example_8765").write_text(KEY + "\n")
        for answer in (None, "", "not an address"):
            self.assertIsNone(owner_mcp.owner_key_file("http://unknown.example:8765", lambda _host: answer))
            self.assertIsNone(owner_mcp.owner_key("http://unknown.example:8765", lookup=lambda _host: answer))
            self.assertIsNone(onboard.owner_computer_key("http://unknown.example:8765", lookup=lambda _host: answer))
        with patch.object(fleet, "HUB", "http://unknown.example:8765"), patch.object(socket, "getaddrinfo", every_address):
            self.assertIsNone(fleet.owner_computer_key())
        self.assertIsNone(owner_mcp.owner_key_file("http://"))

    def test_a_file_that_holds_no_key_is_no_key(self):
        for text in ("", "short", "words that are no key", "a" * 300, KEY + "\nBearer " + OTHER_KEY):
            self.keep(text)
            self.assertIsNone(owner_mcp.owner_key(self.base), text)
            self.assertIsNone(onboard.owner_computer_key(self.base), text)
            with patch.object(fleet, "HUB", self.base):
                self.assertIsNone(fleet.owner_computer_key(), text)

    def test_the_mcp_server_sends_the_key_and_says_what_a_refusal_for_want_of_it_means(self):
        hub.keep_owner_key(sha(KEY))
        refused = owner_mcp.call("GET", "/ui/state", base=self.base)
        self.assertEqual((refused.status, refused.data["auth"]), (403, "owner_key_required"))
        words = str(owner_mcp.refusal(refused, "a read of the fleet"))
        self.assertIn("this server has none for this hub in " + str(self.home / ".founderizer" / "owner-keys"), words)
        self.assertIn("Open Founderizer on this computer once", words)
        self.assertIn("sh hub.sh --reclaim", words)
        self.keep(OTHER_KEY)
        refused = owner_mcp.call("GET", "/ui/state", base=self.base)
        self.assertEqual(refused.data["auth"], "owner_key_mismatch")
        self.assertIn("this server has another one", str(owner_mcp.refusal(refused, "a read")))
        self.assertNotIn(OTHER_KEY, str(owner_mcp.refusal(refused, "a read")))
        self.keep(KEY)                                      # read at each call: the app registered it a moment ago
        self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)
        sent = owner_mcp.call("POST", "/ui/messages", body=dict(self.command(), recipient="manager", text="An order."),
                              base=self.base)
        self.assertEqual(sent.status, 200, sent.data)

    def test_a_hub_with_no_key_gets_the_call_again_with_none(self):
        """A hub from before the key refuses a bearer before it does anything, so the second send is the first one
        that the hub acts on: one message, not two."""
        self.keep(KEY)
        self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)
        sent = owner_mcp.call("POST", "/ui/messages", body=dict(self.command(), recipient="manager", text="An order."),
                              base=self.base)
        self.assertEqual(sent.status, 200, sent.data)
        self.assertEqual(self.count("ui_requests"), 1)

    def test_the_kit_and_the_owner_commands_send_the_key(self):
        hub.keep_owner_key(sha(KEY))
        system = onboard.System(str(self.home / "known_hosts"))
        self.assertEqual(system.http("GET", self.base + "/ui/state")[1].get("auth"), "owner_key_required")
        with patch.object(fleet, "HUB", self.base), patch.object(fleet, "AGENT", None):
            self.assertEqual(fleet.http("GET", "/board.txt")[1].get("auth"), "owner_key_required")
            self.keep(KEY)
            self.assertEqual(fleet.http("GET", "/board.txt")[0], 200)
            self.assertEqual(fleet.http("POST", "/say", {"text": "An order of the owner."})[0], 200)
        self.assertEqual(system.http("GET", self.base + "/ui/state")[0], 200)

    def test_they_send_none_to_a_hub_that_expects_none(self):
        self.keep(KEY)
        self.assertEqual(onboard.System(str(self.home / "known_hosts")).http("GET", self.base + "/ui/state")[0], 200)
        with patch.object(fleet, "HUB", self.base), patch.object(fleet, "AGENT", None):
            self.assertEqual(fleet.http("GET", "/board.txt")[0], 200)

    def test_an_agent_s_helper_never_sends_the_owner_s_key(self):
        """fleet.py on a machine of the fleet calls with its agent's own key, or with none: the file of the owner's
        computer is for the owner's commands only, also when such a file is there."""
        self.keep(KEY)
        sent = []
        with patch.object(fleet, "HUB", self.base), patch.object(fleet, "AGENT", "manager"), \
                patch.object(fleet, "load_agent_key", lambda _agent: None), \
                patch.object(fleet, "http_once", lambda method, path, data, timeout, key: sent.append(key) or (200, {})):
            fleet.http("GET", "/helper/manager")
        self.assertEqual(sent, [None])

    def test_one_hub_address_has_one_key_file_named_by_its_number(self):
        """The claim's own line writes the file under the hub's number. A program that calls the same hub by its name
        on the private network looks the name up and reads that file. So there is no file of another spelling that
        could hold an older key: after a second claim, every program has the new key. While the folder holds no file
        of that port nothing is looked up, and a name that is another address finds nothing."""
        port = self.base.rsplit(":", 1)[1]
        asked = []

        def lookup(host):
            asked.append(host)
            return {"hub-1.tail1234.ts.net": "127.0.0.1", "other.tail1234.ts.net": "127.0.0.9"}.get(host)
        by_name = f"http://hub-1.tail1234.ts.net:{port}"
        self.assertIsNone(owner_mcp.owner_key(by_name, lookup=lookup))
        self.assertIsNone(onboard.owner_computer_key(by_name + "/ui/state", lookup=lookup))
        self.assertEqual(asked, [])                                     # no file of that port: nothing to find
        self.keep(KEY)                                                  # under 127.0.0.1, as the claim writes it
        self.assertEqual(owner_mcp.owner_key(by_name, lookup=lookup), KEY)
        self.assertEqual(onboard.owner_computer_key(by_name + "/ui/state", lookup=lookup), KEY)
        self.assertEqual(owner_mcp.owner_key_file(by_name, lookup), self.file)      # and a key is written there too
        self.assertIsNone(owner_mcp.owner_key(f"http://other.tail1234.ts.net:{port}", lookup=lookup))
        self.assertIsNone(onboard.owner_computer_key(f"http://other.tail1234.ts.net:{port}/ui/state", lookup=lookup))
        self.assertIsNone(owner_mcp.owner_key("http://hub-1.tail1234.ts.net:9", lookup=lookup))    # another port
        # The key of one port of a host is no key of another port of it, also when the folder has a file of that
        # other port (of another host), so that the name is looked up.
        beside = int(port) + 1 if int(port) < 65535 else int(port) - 1
        self.file.with_name(f"127.0.0.9_{beside}").write_text(OTHER_KEY + "\n")
        self.assertIsNone(owner_mcp.owner_key(f"http://hub-1.tail1234.ts.net:{beside}", lookup=lookup))
        self.assertIsNone(onboard.owner_computer_key(f"http://hub-1.tail1234.ts.net:{beside}/ui/state", lookup=lookup))
        self.assertEqual(owner_mcp.owner_key(f"http://other.tail1234.ts.net:{beside}", lookup=lookup), OTHER_KEY)
        self.file.with_name(f"127.0.0.9_{beside}").unlink()
        # A file with the name as it is written (no program writes one) is never the key: with a number the file of
        # the number is, and a name that has no number now has no key.
        written = self.file.with_name(f"hub-1.tail1234.ts.net_{port}")
        written.write_text(OTHER_KEY + "\n")
        self.assertEqual(owner_mcp.owner_key(by_name, lookup=lookup), KEY)
        self.assertEqual(onboard.owner_computer_key(by_name + "/ui/state", lookup=lookup), KEY)
        self.assertIsNone(owner_mcp.owner_key(by_name, lookup=lambda _host: None))
        self.assertIsNone(onboard.owner_computer_key(by_name, lookup=lambda _host: None))
        written.unlink()
        # The hub took a key of the program that calls by name: it is the key of the number.
        with patch.object(owner_mcp, "host_address", lookup):
            owner_mcp.keep_owner_key(by_name, "new-key-" + "c" * 35)
        self.assertEqual(self.file.read_text().strip(), "new-key-" + "c" * 35)
        self.assertEqual(sorted(p.name for p in self.file.parent.iterdir()), [self.file.name])
        # With no number for the name there is no place: nothing is written, and a claim sends nothing.
        with patch.object(owner_mcp, "host_address", lambda _host: None):
            with self.assertRaises(OSError):
                owner_mcp.keep_owner_key(by_name, KEY)
            sent = []
            with patch.object(owner_mcp, "next_step", lambda _what: None), \
                    patch.object(owner_mcp.OPENER, "open", lambda *a, **k: sent.append(a)), \
                    self.assertRaises(owner_mcp.Refused) as said:
                owner_mcp._claim_post("http://127.0.0.1:9", CODE, by_name)
        self.assertIn("no numeric address", str(said.exception))
        self.assertEqual(sent, [])
        self.assertEqual(self.file.read_text().strip(), "new-key-" + "c" * 35)
        self.assertEqual(sorted(p.name for p in self.file.parent.iterdir()), [self.file.name])

    def test_a_call_with_the_key_goes_to_the_hub_s_number_and_never_to_its_name(self):
        """A connection looks a name up by itself, and that second answer can be another host than the first: a name
        that somebody else controls could answer the hub's number to the one and its own host to the other, and get
        the key. So one lookup decides the key and where the call goes."""
        port = self.base.rsplit(":", 1)[1]
        by_name = f"http://hub-1.tail1234.ts.net:{port}"
        self.keep(KEY)
        asked, sent, answers = [], [], []

        def turning(host):                  # the hub's number first, and then somebody else's host
            asked.append(host)
            return "127.0.0.1" if len(asked) == 1 else "127.0.0.9"

        def one_call(method, path, body, base, timeout, limit, mime, extra, total, into, key):
            sent.append((base, key))
            return answers.pop(0) if answers else owner_mcp.Answer(200, {}, b"{}", {})
        with patch.object(owner_mcp, "host_address", turning), patch.object(owner_mcp, "_call", one_call):
            self.assertEqual(owner_mcp.call("GET", "/ui/state", base=by_name).status, 200)
            self.assertEqual(asked, ["hub-1.tail1234.ts.net"])                  # one lookup for the call
            self.assertEqual(sent, [(self.base, KEY)])                          # to the number, with the key
            self.assertEqual(owner_mcp.call("GET", "/ui/state", base=by_name).status, 200)
            self.assertEqual(sent[1:], [(by_name, None)])                       # another host now: no key for it
            # A hub from before the key: the call with the key went to the number, and the call with none goes as
            # its address is written.
            del asked[:], sent[:]
            answers.append(owner_mcp.Answer(403, {"auth": "key_not_expected"}, b"", {}))
            self.assertEqual(owner_mcp.call("GET", "/ui/state", base=by_name).status, 200)
            self.assertEqual(sent, [(self.base, KEY), (by_name, None)])
        owner_mcp.NO_KEY.clear()
        # The kit and the owner's commands: the same one lookup.
        self.assertEqual(onboard.owner_computer_call(by_name + "/ui/state?db=g1", lookup=lambda _host: "127.0.0.1"),
                         (KEY, self.base + "/ui/state?db=g1"))
        self.assertEqual(onboard.owner_computer_call(by_name + "/ui/state", lookup=lambda _host: "127.0.0.9"),
                         (None, by_name + "/ui/state"))
        looked = []

        def every_address(host, *_more, **_named):
            looked.append(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1" if len(looked) == 1 else "127.0.0.9", 0))]
        with patch.object(fleet, "HUB", by_name), patch.object(socket, "getaddrinfo", every_address):
            self.assertEqual(fleet.owner_computer_call(), (KEY, self.base))
            self.assertEqual(looked, ["hub-1.tail1234.ts.net"])
            self.assertEqual(fleet.owner_computer_call(), (None, by_name))
        # A hub that is written as a number is called as it is written, and nothing is looked up.
        with patch.object(owner_mcp, "host_address", lambda host: self.fail(f"a lookup of {host}")):
            self.assertEqual(owner_mcp.owner_key_sent(self.base)[3], self.base)
        self.assertEqual(onboard.owner_computer_call(self.base + "/ui/state", lookup=self.fail),
                         (KEY, self.base + "/ui/state"))
        self.assertEqual(owner_mcp.owner_key_place("http://[fd7a:115c:a1e0::1]:8765")[1], "http://[fd7a:115c:a1e0::1]:8765")

    def test_the_kit_and_the_owner_commands_call_the_hub_s_number_with_the_key(self):
        """The whole call of each, not only the function that finds the key: a hub by its name, the key to its number,
        and the call with no key (a hub from before the key) to the address as it is written."""
        port = self.base.rsplit(":", 1)[1]
        by_name = f"http://hub-1.tail1234.ts.net:{port}"
        self.keep(KEY)

        def every_address(host, *_more, **_named):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]
        sent, answers = [], []

        def kit_call(method, url, body, headers, key):
            sent.append((url, key))
            return answers.pop(0) if answers else (200, {})

        def command_call(method, path, data, timeout, key, base=None):
            sent.append(((base or fleet.HUB) + path, key))
            return answers.pop(0) if answers else (200, {})
        system = onboard.System(str(self.home / "known_hosts"))
        with patch.object(socket, "getaddrinfo", every_address), patch.object(system, "http_once", kit_call), \
                patch.object(fleet, "HUB", by_name), patch.object(fleet, "AGENT", None), \
                patch.object(fleet, "http_once", command_call):
            self.assertEqual(system.http("GET", by_name + "/ui/state?db=g1")[0], 200)
            self.assertEqual(fleet.http("GET", "/board.txt")[0], 200)
            self.assertEqual(sent, [(self.base + "/ui/state?db=g1", KEY), (self.base + "/board.txt", KEY)])
            del sent[:]
            answers.extend([(403, {"auth": "key_not_expected"}), (200, {}), (403, {"auth": "key_not_expected"}), (200, {})])
            self.assertEqual(system.http("GET", by_name + "/ui/state")[0], 200)
            self.assertEqual(fleet.http("GET", "/board.txt")[0], 200)
            self.assertEqual(sent, [(self.base + "/ui/state", KEY), (by_name + "/ui/state", None),
                                    (self.base + "/board.txt", KEY), (by_name + "/board.txt", None)])

    def test_a_redirect_is_an_answer_and_never_carries_the_key_on(self):
        """`urllib` sends a redirected request with the same headers. A program at the hub's number that answers 302
        must not get this computer's key sent to the place that it names."""
        seen = []

        class Elsewhere(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_GET(self):
                seen.append((self.server.server_address[1], self.headers.get("Authorization")))
                if self.server is first:
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{second.server_address[1]}/ui/state")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", "2")
                    self.end_headers()
                    self.wfile.write(b"{}")
        first, second = (http.server.HTTPServer(("127.0.0.1", 0), Elsewhere) for _ in range(2))
        for server in (first, second):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 5)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{first.server_address[1]}"
        self.file.with_name(f"127.0.0.1_{first.server_address[1]}").parent.mkdir(mode=0o700, exist_ok=True)
        self.file.with_name(f"127.0.0.1_{first.server_address[1]}").write_text(KEY + "\n")
        with patch.object(owner_mcp, "next_step", lambda _what: None):
            self.assertEqual(owner_mcp.call("GET", "/ui/state", base=base).status, 302)
        self.assertEqual(onboard.System(str(self.home / "known_hosts")).http("GET", base + "/ui/state")[0], 302)
        with patch.object(fleet, "HUB", base), patch.object(fleet, "AGENT", None):
            self.assertEqual(fleet.http("GET", "/ui/state")[0], 302)
        self.assertEqual(seen, [(first.server_address[1], "Bearer " + KEY)] * 3)        # and nothing went on

    def test_a_claim_by_a_name_goes_to_the_number_that_names_the_key_s_file(self):
        """The answer that makes the key this computer's key comes from the host whose number the file has. With the
        claim sent to the name again, another host could answer `kept` and put its word in place of the real hub's
        key."""
        server, listener = self.listener()
        lport, port = listener.rsplit(":", 1)[1], self.base.rsplit(":", 1)[1]
        opened = []
        real = owner_mcp.OPENER.open

        def opening(request, *args, **named):
            opened.append(request.full_url)
            return real(request, *args, **named)
        with patch.object(owner_mcp, "next_step", lambda _what: None), \
                patch.object(owner_mcp, "host_address", lambda _host: "127.0.0.1"), \
                patch.object(owner_mcp.OPENER, "open", opening):
            got = owner_mcp._claim_post(f"http://hub-1.tail1234.ts.net:{lport}", CODE, f"http://hub-1.tail1234.ts.net:{port}")
        self.assertEqual(got.status, 200)
        self.assertEqual(opened, [f"http://127.0.0.1:{lport}/claim"])
        self.assertEqual(sha(self.file.read_text().strip()), server.owner_key)

    def test_the_key_that_waits_goes_once_when_the_hub_holds_another_key_than_the_key(self):
        """A claim or a registration whose answer was lost, on a computer that has a key from before: the hub holds
        the key that waits. The hub refuses the key from before, and the same call goes once more with the one that
        waits, which then is the key."""
        pending = self.file.with_name(self.file.name + ".pending")
        self.keep(KEY)
        pending.write_text(OTHER_KEY + "\n")
        hub.keep_owner_key(sha(OTHER_KEY))
        with patch.object(owner_mcp, "next_step", lambda _what: None):
            self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)
            self.assertEqual(self.file.read_text().strip(), OTHER_KEY)
            self.assertFalse(pending.exists())
            # A key that waits and that the hub does not hold either: the hub's own refusal of the key comes back,
            # and the key still waits.
            third = "mac-key-" + "c" * 35
            hub.keep_owner_key(sha(third))
            pending.write_text(KEY + "\n")
            answer = owner_mcp.call("GET", "/ui/state", base=self.base)
            self.assertEqual((answer.status, answer.data["auth"]), (403, "owner_key_mismatch"))
            self.assertEqual((self.file.read_text().strip(), pending.read_text().strip()), (OTHER_KEY, KEY))

    def test_a_key_that_waits_goes_to_the_hub_s_number_too(self):
        """The hub can hold the key that waits, so it is the same secret as the key: at its first send (no key
        beside it) and at its second (the hub refused the key from before), it goes to the number and never to the
        name."""
        port = self.base.rsplit(":", 1)[1]
        by_name = f"http://hub-1.tail1234.ts.net:{port}"
        pending = self.file.with_name(self.file.name + ".pending")
        self.file.parent.mkdir(mode=0o700, exist_ok=True)
        pending.write_text(OTHER_KEY + "\n")
        sent, answers = [], []

        def one_call(method, path, body, base, timeout, limit, mime, extra, total, into, key):
            sent.append((base, key))
            return answers.pop(0) if answers else owner_mcp.Answer(200, {}, b"{}", {})
        with patch.object(owner_mcp, "host_address", lambda _host: "127.0.0.1"), patch.object(owner_mcp, "_call", one_call):
            self.assertEqual(owner_mcp.call("GET", "/ui/state", base=by_name).status, 200)
            self.assertEqual(sent, [(self.base, OTHER_KEY)])                    # the first send of a key that waits
            self.assertEqual(self.file.read_text().strip(), OTHER_KEY)          # and the hub took it
            del sent[:]
            pending.write_text(KEY + "\n")
            answers.append(owner_mcp.Answer(403, {"auth": "owner_key_mismatch"}, b"", {}))
            self.assertEqual(owner_mcp.call("POST", "/ui/message", {"text": "one"}, base=by_name).status, 200)
            self.assertEqual(sent, [(self.base, OTHER_KEY), (self.base, KEY)])  # the second try, to the number too
            self.assertEqual(self.file.read_text().strip(), KEY)

    def test_a_claim_listener_of_another_host_must_be_written_as_a_number(self):
        """`claim_hub` gives the listener and the hub one host. A listener of another host by a name would take the
        claim code to whoever answers that name."""
        opened = []
        with patch.object(owner_mcp, "next_step", lambda _what: None), \
                patch.object(owner_mcp.OPENER, "open", lambda *a, **k: opened.append(a)), \
                patch.object(owner_mcp, "host_address", lambda host: self.fail(f"a lookup of {host}")), \
                self.assertRaises(owner_mcp.Refused) as said:
            owner_mcp._claim_post("http://listener.tail1234.ts.net:8765", CODE, "http://100.64.0.9:8765")
        self.assertIn("two hosts", str(said.exception))
        self.assertEqual(opened, [])
        self.assertEqual(list(self.file.parent.glob("*")) if self.file.parent.exists() else [], [])

    def test_one_address_has_one_spelling_and_a_name_with_two_addresses_has_one_number(self):
        """As in the app (`OwnerMacKey.canonical`, `OwnerMacKey.chosen`): the same file for the same hub, whichever
        program asks and in whatever order a resolver gives a name's addresses."""
        for module in (owner_mcp, onboard):
            self.assertEqual(module.canonical_address("100.64.0.9"), "100.64.0.9")
            self.assertEqual(module.canonical_address("FD7A:115C:A1E0:0:0:0:0:1"), "fd7a:115c:a1e0::1")
            for text in ("", "hub.example", "100.64.0", "100.64.0.9.1", "fd7a::1::2", None):
                self.assertIsNone(module.canonical_address(text), text)
            for addresses, chosen in ((["192.0.2.28", "100.64.0.9", "fd7a:115c:a1e0::1"], "100.64.0.9"),
                                      (["fd7a:115c:a1e0::1", "100.64.0.9", "192.0.2.28"], "100.64.0.9"),
                                      (["192.0.2.28", "192.0.2.5"], "192.0.2.5"), (["192.0.2.5", "192.0.2.28"], "192.0.2.5"),
                                      (["100.64.0.10", "100.64.0.9"], "100.64.0.9"),
                                      (["10.0.0.9", "100.64.0.9"], "100.64.0.9"), (["100.64.0.9", "10.0.0.9"], "100.64.0.9"),
                                      (["fd7a:115c:a1e0::2", "FD7A:115C:A1E0::1"], "fd7a:115c:a1e0::1"),
                                      ([], None), (["not an address"], None)):
                self.assertEqual(module.chosen_address(addresses), chosen, addresses)
        long, short = "http://[fd7a:115c:a1e0:0:0:0:0:1]:8765", "http://[fd7a:115c:a1e0::1]:8765"
        self.assertEqual(owner_mcp.owner_key_file(long), owner_mcp.owner_key_file(short))
        self.assertEqual(owner_mcp.owner_key_place(long)[1], short)
        folder = self.file.parent
        folder.mkdir(mode=0o700, exist_ok=True)
        (folder / "fd7a-115c-a1e0--1_8765").write_text(KEY + "\n")
        self.assertEqual(onboard.owner_computer_call(long + "/ui/state"), (KEY, short + "/ui/state"))
        # Two addresses outside the fleet's private network: the lowest one, whatever the order. Each program has
        # its own copy of this rule.
        (folder / "192.0.2.5_8765").write_text(KEY + "\n")
        for order in (["192.0.2.28", "192.0.2.5"], ["192.0.2.5", "192.0.2.28"], ["fd7a:115c:a1e0::9", "192.0.2.28", "192.0.2.5"]):
            def every_plain_address(host, *_more, **_named):
                return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in order]
            with patch.object(socket, "getaddrinfo", every_plain_address), patch.object(fleet, "HUB", "http://hub.example:8765"):
                self.assertEqual(fleet.owner_computer_call(), (KEY, "http://192.0.2.5:8765"), order)
                self.assertEqual(owner_mcp.owner_key_sent("http://hub.example:8765")[3], "http://192.0.2.5:8765", order)
                self.assertEqual(onboard.owner_computer_call("http://hub.example:8765/x")[1], "http://192.0.2.5:8765/x")
        (folder / "192.0.2.5_8765").unlink()
        (folder / "100.64.0.9_8765").write_text(OTHER_KEY + "\n")
        for order in (["192.0.2.28", "100.64.0.9"], ["100.64.0.9", "192.0.2.28"], ["10.0.0.9", "100.64.0.9"],
                      ["100.64.0.9", "10.0.0.9"]):          # the private network first, also where it is not the lowest
            def every_address(host, *_more, **_named):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in order]
            with patch.object(socket, "getaddrinfo", every_address), patch.object(fleet, "HUB", "http://hub.example:8765"):
                self.assertEqual(fleet.owner_computer_call(), (OTHER_KEY, "http://100.64.0.9:8765"), order)
                self.assertEqual(owner_mcp.owner_key_sent("http://hub.example:8765")[3], "http://100.64.0.9:8765", order)
                self.assertEqual(onboard.owner_computer_call("http://hub.example:8765/x")[1], "http://100.64.0.9:8765/x")
        with patch.object(fleet, "HUB", long):
            self.assertEqual(fleet.owner_computer_call(), (KEY, short))

    def test_an_answer_of_a_route_that_asks_for_no_key_makes_no_key_of_the_one_that_waits(self):
        """`GET /health` and the agents' routes answer 2xx to anybody. Only an owner route's 2xx says that the hub
        took the key."""
        pending = self.file.with_name(self.file.name + ".pending")
        self.file.parent.mkdir(mode=0o700, exist_ok=True)
        pending.write_text(KEY + "\n")

        def one_call(*args):
            return owner_mcp.Answer(200, {}, b"{}", {})
        with patch.object(owner_mcp, "_call", one_call):
            for path in ("/health", "/outbox", "/join", "/ui/owner/key"):
                owner_mcp.call("GET", path, base=self.base)
                self.assertFalse(self.file.exists(), path)
                self.assertEqual(pending.read_text().strip(), KEY, path)
            owner_mcp.call("GET", "/ui/state", base=self.base)
        self.assertEqual(self.file.read_text().strip(), KEY)
        self.assertFalse(pending.exists())

    def test_the_key_that_the_hub_took_is_kept_whatever_waits_beside_it(self):
        """Two programs of this computer claim or register at one time: the second one's key waits in the file by the
        time the hub's yes to the first one arrives. The first one's key is the key, and the other one still waits."""
        server, base = self.listener()
        pending = self.file.with_name(self.file.name + ".pending")
        real = owner_mcp.write_owner_key

        def write_and_then_another_program_writes(path, key):
            real(path, key)
            if str(path).endswith(".pending"):
                Path(path).write_text(OTHER_KEY + "\n")                 # the other program's key waits there now
        with patch.object(owner_mcp, "next_step", lambda _what: None), \
                patch.object(owner_mcp, "write_owner_key", write_and_then_another_program_writes):
            self.assertEqual(owner_mcp._claim_post(base, CODE, self.base).status, 200)
        self.assertEqual(sha(self.file.read_text().strip()), server.owner_key)      # the key that the hub holds
        self.assertEqual(pending.read_text().strip(), OTHER_KEY)

    def test_a_hub_that_expects_no_key_gets_each_later_call_once(self):
        """Each refused call is one line of the hub's log. The MCP server runs for as long as its session: after the
        first answer `key_not_expected` it sends that hub no key, until this computer's key is another one."""
        self.keep(KEY)
        sent, real = [], owner_mcp._call

        def counted(*args):
            sent.append(args[-1])
            return real(*args)
        with patch.object(owner_mcp, "_call", counted), patch.dict(owner_mcp.NO_KEY, clear=True):
            for _ in range(3):
                self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)
            self.assertEqual(sent, [KEY, None, None, None])
            self.keep(OTHER_KEY)                                        # a new key is no key that the hub refused
            hub.keep_owner_key(sha(OTHER_KEY))
            self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)
            self.assertEqual(sent[-1], OTHER_KEY)
            # The hub once expected no key, and it holds this computer's own key now (a claim that was made again
            # sent the key that waited): the first refusal for want of a key ends the memory.
            hub.OWNER_KEY.update(stamp=None, value=None)
            (self.folder / hub.OWNER_KEY_FILE).unlink()
            self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)
            self.assertEqual(owner_mcp.NO_KEY, {self.base: OTHER_KEY})
            hub.keep_owner_key(sha(OTHER_KEY))
            del sent[:]
            self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)
            self.assertEqual((sent, owner_mcp.NO_KEY), ([None, OTHER_KEY], {}))

    # ---- the claim of the MCP server, against the real listener of hubsetup.py

    def listener(self, keeps=True):
        server = hubsetup.ClaimServer(("127.0.0.1", 0), "127.0.0.2", 8765, sha(CODE))
        server.timeout = 1
        self.addCleanup(server.server_close)
        if not keeps:           # an installer from before the key: its answer names no key
            old = patch.object(hubsetup, "OWNER_KEY_KEPT", "X-Nothing")
            old.start()
            self.addCleanup(old.stop)

        def serve():
            for _ in range(4):
                if server.owner is not None:
                    break
                server.handle_request()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        return server, "http://127.0.0.1:%d" % server.server_address[1]

    def test_the_claim_of_the_mcp_server_makes_the_key_and_keeps_it_when_the_installer_does(self):
        server, base = self.listener()
        with patch.object(owner_mcp, "next_step", lambda _what: None):
            answer = owner_mcp._claim_post(base, CODE, "http://100.64.0.9:8765")
        self.assertEqual(answer.status, 200)
        path = owner_mcp.owner_key_file("http://100.64.0.9:8765")
        key = path.read_text(encoding="utf-8").strip()
        self.assertRegex(key, r"^[A-Za-z0-9_-]{43}$")
        self.assertEqual(server.owner_key, sha(key))
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name])      # nothing pending is left

    def test_a_claim_that_was_refused_or_met_an_old_installer_makes_no_key(self):
        server, base = self.listener()
        with patch.object(owner_mcp, "next_step", lambda _what: None):
            self.assertEqual(owner_mcp._claim_post(base, "WRONGWRONGWR", "http://100.64.0.9:8765").status, 403)
        path = owner_mcp.owner_key_file("http://100.64.0.9:8765")
        # No key, and the key that waits stays: it can be the key of an earlier claim whose answer was lost.
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name + ".pending"])
        self.assertIsNone(server.owner_key)
        server, base = self.listener(keeps=False)
        with patch.object(owner_mcp, "next_step", lambda _what: None):
            self.assertEqual(owner_mcp._claim_post(base, CODE, "http://100.64.0.9:8765").status, 200)
        self.assertEqual(list(path.parent.iterdir()), [])              # the claim went through, and it keeps no key

    def test_a_second_claim_after_a_lost_answer_sends_the_key_that_waits(self):
        """The listener took the first claim and its SHA-256, and the answer did not arrive. The agent calls claim_hub
        again: a new key would be one that the hub does not hold, and it would take the place of the one it holds."""
        taken = []

        def lost(request, timeout=None):
            taken.append(request.get_header("X-fleet-owner-key-sha256"))
            raise OSError("the answer did not come")
        for _ in range(2):
            with patch.object(owner_mcp, "next_step", lambda _what: None), \
                    patch.object(owner_mcp.OPENER, "open", lost), self.assertRaises(owner_mcp.Refused):
                owner_mcp._claim_post("http://127.0.0.1:9", CODE, self.base)
        server, base = self.listener()
        with patch.object(owner_mcp, "next_step", lambda _what: None):
            self.assertEqual(owner_mcp._claim_post(base, "WRONGWRONGWR", self.base).status, 403)   # a refusal takes none
        pending = self.file.with_name(self.file.name + ".pending")
        self.assertEqual(taken, [sha(pending.read_text().strip())] * 2)
        hub.keep_owner_key(taken[0])
        self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)
        self.assertEqual(sha(self.file.read_text().strip()), taken[0])

    def test_a_claim_whose_answer_was_lost_keeps_its_key_for_the_hub_that_took_it(self):
        """The listener kept the SHA-256 and its answer did not arrive. The key waits as pending: the first call that
        the hub takes with it makes it this computer's key, so a lost answer costs no second claim."""
        taken = []

        def lost(request, timeout=None):
            taken.append(request.get_header("X-fleet-owner-key-sha256"))
            raise OSError("the answer did not come")
        with patch.object(owner_mcp, "next_step", lambda _what: None), patch.object(owner_mcp.OPENER, "open", lost), \
                self.assertRaises(owner_mcp.Refused):
            owner_mcp._claim_post("http://127.0.0.1:9", CODE, self.base)
        self.assertFalse(self.file.exists())
        pending = self.file.with_name(self.file.name + ".pending")
        self.assertEqual(taken, [sha(pending.read_text().strip())])
        hub.keep_owner_key(taken[0])                        # the hub that the claim made holds that SHA-256
        self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)
        self.assertTrue(self.file.exists())
        self.assertFalse(pending.exists())
        self.assertEqual(sha(self.file.read_text().strip()), taken[0])

    def test_a_pending_key_that_the_hub_does_not_take_stays_pending(self):
        self.file.parent.mkdir(mode=0o700)
        pending = self.file.with_name(self.file.name + ".pending")
        pending.write_text(KEY + "\n")
        self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).status, 200)        # no key on the hub
        self.assertTrue(pending.exists())
        self.assertFalse(self.file.exists())
        with patch.dict(owner_mcp.NO_KEY, clear=True):
            hub.keep_owner_key(sha(KEY))                                # the hub holds it, and the answer is no 2xx:
            self.assertEqual(owner_mcp.call("GET", "/ui/nothing-here", base=self.base).status, 404)
            self.assertFalse(self.file.exists())                        # a 404 came before the owner's rule
        hub.keep_owner_key(sha(OTHER_KEY))
        self.assertEqual(owner_mcp.call("GET", "/ui/state", base=self.base).data["auth"], "owner_key_mismatch")
        self.assertFalse(self.file.exists())


class Claim(unittest.TestCase):
    """hubsetup.py: the claim of the hub's own server takes the SHA-256 of the key beside its one-time code."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fleet-owner-key-"))
        self.addCleanup(shutil.rmtree, str(self.tmp), True)
        self.out, self.db = str(self.tmp / "team.json"), str(self.tmp / "records" / "pilot.db")
        self.said, self.sent, self.owner, self.error = [], {}, [], []
        for one in (patch.object(hubsetup, "new_code", lambda: (CODE, SHOWN)),
                    patch.object(hubsetup, "say", self.said.append),
                    patch("builtins.print", lambda *a, **k: None)):
            one.start()
            self.addCleanup(one.stop)

    def start(self):
        """The real claim, in a thread, on the loopback with a free port. Its base address."""
        def run():
            try:
                self.owner.append(hubsetup.claim(HUB_IP, 8765, wait=20, where=("127.0.0.1", 0), sent=self.sent))
            except Exception as e:
                self.error.append(e)
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        self.addCleanup(self.thread.join, 5)
        for _ in range(200):
            line = next((s for s in self.said if "the owner claim is open on" in s), None)
            if line:
                return "http://127.0.0.1:" + line.split(" for ")[0].rsplit(":", 1)[1]
            threading.Event().wait(0.02)
        self.fail("the claim did not open")

    def post(self, base, body, headers=None):
        request = urllib.request.Request(base + "/claim", data=body, method="POST", headers=headers or {})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=5) as answer:
                return answer.status, dict(answer.headers)
        except urllib.error.HTTPError as answer:
            with answer:
                return answer.code, dict(answer.headers)

    def test_the_claim_takes_the_sha_beside_the_code_and_says_that_it_keeps_it(self):
        base = self.start()
        status, headers = self.post(base, SHOWN.encode(), {hubsetup.OWNER_KEY_HEADER: sha(KEY)})
        self.assertEqual((status, headers.get(hubsetup.OWNER_KEY_KEPT)), (200, "kept"))
        self.thread.join(5)
        self.assertEqual((self.owner, self.sent), (["127.0.0.1"], {"owner_key": sha(KEY)}))

    def test_a_claim_from_before_the_key_sends_none_and_is_told_nothing(self):
        base = self.start()
        status, headers = self.post(base, SHOWN.encode())
        self.assertEqual(status, 200)
        self.assertNotIn(hubsetup.OWNER_KEY_KEPT, headers)
        self.thread.join(5)
        self.assertEqual(self.sent, {"owner_key": None})

    def test_a_sha_that_is_none_uses_no_code_and_no_try(self):
        base = self.start()
        for wrong in ("", "x", "A" * 64, "a" * 63, KEY):
            self.assertEqual(self.post(base, SHOWN.encode(), {hubsetup.OWNER_KEY_HEADER: wrong})[0], 400, wrong)
        for _ in range(hubsetup.CLAIM_TRIES + 1):       # more of them than wrong codes are allowed
            self.assertEqual(self.post(base, SHOWN.encode(), {hubsetup.OWNER_KEY_HEADER: "nothing"})[0], 400)
        self.assertEqual(self.post(base, SHOWN.encode(), {hubsetup.OWNER_KEY_HEADER: sha(KEY)})[0], 200)

    def test_a_wrong_code_keeps_no_sha(self):
        base = self.start()
        self.assertEqual(self.post(base, b"WRONG-WRONG-WRNG", {hubsetup.OWNER_KEY_HEADER: sha(OTHER_KEY)})[0], 403)
        self.assertEqual(self.post(base, SHOWN.encode(), {hubsetup.OWNER_KEY_HEADER: sha(KEY)})[0], 200)
        self.thread.join(5)
        self.assertEqual(self.sent, {"owner_key": sha(KEY)})

    def test_the_sha_of_a_refused_call_is_not_the_key_of_a_later_claim(self):
        """A caller that does not know the code sends a SHA-256 of its own. The claim that follows, from a program
        from before the key, must keep no key at all: never the one of the refused call."""
        base = self.start()
        self.assertEqual(self.post(base, b"WRONG-WRONG-WRNG", {hubsetup.OWNER_KEY_HEADER: sha(OTHER_KEY)})[0], 403)
        self.assertEqual(self.post(base, SHOWN.encode())[0], 200)
        self.thread.join(5)
        self.assertEqual(self.sent, {"owner_key": None})

    def test_the_claim_s_own_command_line_keeps_the_key_where_the_hub_reads_it(self):
        """`hub.sh` gives the claim no --db, and the hub's service gives hub.py none: both take their own default,
        and the two must be one folder, or the claim writes a file that no hub reads."""
        seen = []
        with patch.object(hubsetup, "cmd_claim", seen.append):
            hubsetup.main(["claim", "--address", HUB_IP, "--out", self.out, "--commit"])
        self.assertEqual(seen[0].db, hubsetup.DB_PATH)
        self.assertEqual(os.path.expanduser(hubsetup.DB_PATH), os.path.expanduser(hub.DB_DEFAULT))
        self.assertEqual(hubsetup.owner_key_file(hubsetup.DB_PATH),
                         os.path.join(os.path.dirname(os.path.expanduser(hub.DB_DEFAULT)), hub.OWNER_KEY_FILE))

    def test_a_claim_that_commits_keeps_the_key_as_one_that_does_not(self):
        """`hub.sh` always gives --commit."""
        with self.claimed("100.64.0.4", sha(KEY)), patch.object(hubsetup, "commit_team") as commit:
            hubsetup.cmd_claim(self.args(commit=True))
        commit.assert_called_once()
        self.assertEqual(json.loads(Path(hubsetup.owner_key_file(self.db)).read_text())["sha256"], sha(KEY))

    def test_the_key_is_kept_before_the_owner_is_named(self):
        """A claim that stops between the two leaves a hub that asks for the key, and never a hub that has an owner
        and knows it by its address alone."""
        order = []
        real_keep, real_write = hubsetup.keep_owner_key, hubsetup.write_team
        with self.claimed("100.64.0.4", sha(KEY)), \
                patch.object(hubsetup, "keep_owner_key", lambda *a: order.append("key") or real_keep(*a)), \
                patch.object(hubsetup, "write_team", lambda *a: order.append("team") or real_write(*a)):
            hubsetup.cmd_claim(self.args())
        self.assertEqual(order, ["key", "team"])
        # team.json cannot be written: the first claim stops, and it left no owner with no key
        os.remove(self.out)
        with self.claimed("100.64.0.4", sha(OTHER_KEY)), self.assertRaises(OSError), \
                patch.object(hubsetup, "write_team", lambda *a: (_ for _ in ()).throw(OSError("the disk is full"))):
            hubsetup.cmd_claim(self.args())
        self.assertFalse(os.path.exists(self.out))
        self.assertEqual(json.loads(Path(hubsetup.owner_key_file(self.db)).read_text())["sha256"], sha(OTHER_KEY))

    def test_a_terminal_that_is_gone_does_not_undo_a_key_that_is_kept(self):
        def gone(_words):
            raise BrokenPipeError("the terminal is gone")
        with self.claimed("100.64.0.4", sha(KEY)), patch.object(hubsetup, "say", gone):
            hubsetup.cmd_claim(self.args())
        self.assertEqual(json.loads(Path(hubsetup.owner_key_file(self.db)).read_text())["sha256"], sha(KEY))
        self.assertEqual(json.loads(Path(self.out).read_text())["addresses"]["owner"], "100.64.0.4")

    def args(self, **changed):
        return type("A", (), dict({"address": HUB_IP, "port": 8765, "out": self.out, "reclaim": False,
                                   "timezone": "UTC", "runtime": "claude", "ssh_user": "fleet", "ssh_port": 22,
                                   "wait": 1, "commit": False, "manager_later": False, "db": self.db}, **changed))()

    def claimed(self, owner, key):
        def claim(*_args, sent=None, **_more):
            sent["owner_key"] = key
            return owner
        return patch.object(hubsetup, "claim", claim)

    def test_the_first_claim_writes_the_key_s_file_beside_the_records_before_the_hub_starts(self):
        """The folder of the records is not there yet at a first claim: the hub has never run."""
        with self.claimed("100.64.0.4", sha(KEY)):
            hubsetup.cmd_claim(self.args())
        path = Path(hubsetup.owner_key_file(self.db))
        self.assertEqual(path, self.tmp / "records" / hub.OWNER_KEY_FILE)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(json.loads(path.read_text())["sha256"], sha(KEY))
        self.assertEqual(json.loads(Path(self.out).read_text())["addresses"]["owner"], "100.64.0.4")
        with patch.dict(hub.CFG, {"owner_key_dir": str(path.parent)}):      # and it is the file that the hub reads
            hub.OWNER_KEY.update(stamp=None, value=None)
            self.assertTrue(hub.owner_key_matches(KEY))
            self.assertFalse(hub.owner_key_matches(OTHER_KEY))
        hub.OWNER_KEY.update(stamp=None, value=None)

    def test_a_second_claim_puts_the_new_owner_s_key_in_place_of_the_old_one(self):
        with self.claimed("100.64.0.4", sha(KEY)):
            hubsetup.cmd_claim(self.args())
        with self.claimed("100.64.0.5", sha(OTHER_KEY)):
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertEqual(json.loads(Path(hubsetup.owner_key_file(self.db)).read_text())["sha256"], sha(OTHER_KEY))
        self.assertEqual(json.loads(Path(self.out).read_text())["addresses"]["owner"], "100.64.0.5")

    def test_a_second_claim_with_no_key_takes_the_old_owner_s_key_away(self):
        """The new owner's program is from before the key, so its computer has none. With the old file left there, the
        hub would ask the new owner for the key of the computer that is gone."""
        with self.claimed("100.64.0.4", sha(KEY)):
            hubsetup.cmd_claim(self.args())
        with self.claimed("100.64.0.5", None):
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertFalse(os.path.exists(hubsetup.owner_key_file(self.db)))
        self.assertIn("no key", " ".join(self.said))

    def test_a_second_claim_that_fails_leaves_the_key_as_it_found_it(self):
        """team.json names the owner from before again, so that owner's key stays with it: a claim of another
        computer that failed must not lock the owner out, and a claim with no key that failed must not open the hub
        to the address alone again."""
        with self.claimed("100.64.0.4", sha(KEY)):
            hubsetup.cmd_claim(self.args())
        path = Path(hubsetup.owner_key_file(self.db))
        found = path.read_bytes()

        def full(*_args):
            raise OSError("the disk is full")
        for owner, key in (("100.64.0.5", sha(OTHER_KEY)), ("100.64.0.5", None), ("100.64.0.4", None)):
            del self.said[:]
            with self.claimed(owner, key), patch.object(hubsetup, "write_team", full), self.assertRaises(OSError):
                hubsetup.cmd_claim(self.args(reclaim=True))
            self.assertEqual(path.read_bytes(), found, (owner, key))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(Path(self.out).read_text())["addresses"]["owner"], "100.64.0.4")
            self.assertEqual([p.name for p in path.parent.iterdir()], [path.name], (owner, key))   # nothing set aside stays
            # a claim with a key says that the key is back; one with none changed nothing of the key
            self.assertEqual("as it was before the claim" in " ".join(self.said), key is not None)
        # The same computer claims again with a new key: it keeps that key from the listener's answer on, so the
        # hub keeps it too, whatever fails after.
        with self.claimed("100.64.0.4", sha(OTHER_KEY)), patch.object(hubsetup, "write_team", full), \
                self.assertRaises(OSError):
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertEqual(json.loads(path.read_text())["sha256"], sha(OTHER_KEY))
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name])

    def test_a_key_comes_back_by_a_rename_also_when_nothing_can_be_written(self):
        """A full disk makes the write of team.json and each later write fail together. The key from before was set
        aside by a rename and comes back by one, and a claim with no key takes the earlier key away only after
        team.json names its computer: neither path leaves an owner with no key."""
        with self.claimed("100.64.0.4", sha(KEY)):
            hubsetup.cmd_claim(self.args())
        path = Path(hubsetup.owner_key_file(self.db))
        found = path.read_bytes()
        real_open = os.open

        def full(*_args):
            raise OSError("the disk is full")

        def no_new_file(name, flags, *more, **named):       # after the claim wrote its key: no file can be made
            if flags & os.O_CREAT and str(name).startswith(str(path)) and blocked:
                raise OSError(28, "No space left on device")
            return real_open(name, flags, *more, **named)
        blocked = []
        real_keep = hubsetup.keep_owner_key

        def keep_then_fill(*args):
            real_keep(*args)
            blocked.append(True)
        for owner, key in (("100.64.0.5", sha(OTHER_KEY)), ("100.64.0.5", None)):
            del blocked[:]
            with self.claimed(owner, key), patch.object(hubsetup, "write_team", full), \
                    patch.object(hubsetup, "keep_owner_key", keep_then_fill), patch.object(os, "open", no_new_file), \
                    self.assertRaises(OSError):
                hubsetup.cmd_claim(self.args(reclaim=True))
            self.assertEqual(path.read_bytes(), found, (owner, key))
        # A claim with no key that goes through takes the earlier key away, after team.json names its computer.
        order = []
        real_write = hubsetup.write_team
        with self.claimed("100.64.0.5", None), \
                patch.object(hubsetup, "write_team", lambda *a: order.append("team") or real_write(*a)), \
                patch.object(hubsetup, "keep_owner_key", lambda *a: order.append("key") or real_keep(*a)):
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertEqual(order, ["team", "key"])
        self.assertFalse(path.exists())

    def test_the_path_of_the_key_holds_a_key_at_each_moment_of_a_second_claim(self):
        """A kill between two steps of a claim leaves a hub that starts again by itself. With the earlier key renamed
        away before the new one is written, that hub would read no key and know the owner by the address alone."""
        with self.claimed("100.64.0.4", sha(KEY)):
            hubsetup.cmd_claim(self.args())
        path = Path(hubsetup.owner_key_file(self.db))
        found, seen = path.read_bytes(), []
        real_keep, real_open = hubsetup.keep_owner_key, os.open

        def looking(name, flags, *more, **named):       # each file that the claim makes: what the path holds then
            if flags & os.O_CREAT and str(name).startswith(str(path)):
                seen.append(path.read_bytes())
            return real_open(name, flags, *more, **named)
        with self.claimed("100.64.0.5", sha(OTHER_KEY)), patch.object(os, "open", looking), \
                patch.object(hubsetup, "keep_owner_key", lambda *a: seen.append(path.read_bytes()) or real_keep(*a)):
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertEqual(seen, [found, found])                      # before the new key, and while it is written
        self.assertEqual(json.loads(path.read_text())["sha256"], sha(OTHER_KEY))
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name])
        # What a claim that was killed left beside the file is no earlier key of a later claim: a later claim that
        # fails puts back the key that it found itself.
        found = path.read_bytes()
        Path(str(path) + ".before").write_text(json.dumps({"sha256": sha(KEY), "since": 1}))

        def full(*_args):
            raise OSError("the disk is full")
        with self.claimed("100.64.0.4", sha(KEY)), patch.object(hubsetup, "write_team", full), self.assertRaises(OSError):
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertEqual(path.read_bytes(), found)
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name])
        # A second claim whose key cannot be kept says what is true of that hub: it keeps its owner and its key.
        def no_room(name, flags, *more, **named):
            if flags & os.O_CREAT and str(name).startswith(str(path)):
                raise OSError(28, "No space left on device")
            return real_open(name, flags, *more, **named)
        with self.claimed("100.64.0.4", sha(KEY)), patch.object(os, "open", no_room), \
                self.assertRaises(hubsetup.Stop) as stopped:
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertIn("is as it was before the claim, with its owner", str(stopped.exception))
        self.assertNotIn("no owner yet", str(stopped.exception))
        self.assertEqual(path.read_bytes(), found)
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name])

    def test_a_hard_link_that_is_refused_never_makes_the_earlier_key_no_key(self):
        """A file system with no hard links: the earlier key is copied aside instead, and a claim that fails puts it
        back. When it cannot be set aside at all, the claim stops with the key in its place. Taken as "no earlier
        key", a claim that fails later would leave the owner with no key: the address rule again."""
        with self.claimed("100.64.0.4", sha(KEY)):
            hubsetup.cmd_claim(self.args())
        path = Path(hubsetup.owner_key_file(self.db))
        found, real_open = path.read_bytes(), os.open

        def no_link(*_args, **_named):
            raise OSError(1, "Operation not permitted")

        def full(*_args):
            raise OSError("the disk is full")
        # The copy stands in for the link: a claim of another computer that fails puts the key back.
        with self.claimed("100.64.0.5", sha(OTHER_KEY)), patch.object(os, "link", no_link), \
                patch.object(hubsetup, "write_team", full), self.assertRaises(OSError):
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertEqual(path.read_bytes(), found)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name])
        # And a claim that goes through has its key, with nothing beside it.
        with self.claimed("100.64.0.4", sha(OTHER_KEY)), patch.object(os, "link", no_link):
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertEqual(json.loads(path.read_text())["sha256"], sha(OTHER_KEY))
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name])
        found = path.read_bytes()
        # Neither a link nor a copy: the claim stops before it writes anything, and the hub is as it was.
        def no_copy(name, flags, *more, **named):
            if str(name).endswith(".before"):
                raise OSError(28, "No space left on device")
            return real_open(name, flags, *more, **named)
        with self.claimed("100.64.0.5", sha(KEY)), patch.object(os, "link", no_link), patch.object(os, "open", no_copy), \
                patch.object(hubsetup, "write_team", lambda *a: self.fail("it wrote team.json")), \
                self.assertRaises(hubsetup.Stop) as stopped:
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertIn("could not be set aside", str(stopped.exception))
        self.assertEqual(path.read_bytes(), found)
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name])
        self.assertEqual(json.loads(Path(self.out).read_text())["addresses"]["owner"], "100.64.0.4")
        # A link whose file is gone stands at the path: the hub reads it as a damaged key file and refuses each
        # caller. It is never "no earlier key": a claim that then fails would leave no key file, the address rule.
        path.unlink()
        path.symlink_to(path.parent / "a-file-that-is-gone")
        with self.claimed("100.64.0.5", sha(KEY)), patch.object(hubsetup, "write_team", full), \
                self.assertRaises((hubsetup.Stop, OSError)):
            hubsetup.cmd_claim(self.args(reclaim=True))
        self.assertTrue(path.is_symlink())                              # as the claim found it
        self.assertEqual([p.name for p in path.parent.iterdir()], [path.name])
        self.assertEqual(json.loads(Path(self.out).read_text())["addresses"]["owner"], "100.64.0.4")

    def test_a_second_claim_whose_push_fails_puts_the_key_back_with_team_json(self):
        """With --commit, as `hub.sh` runs it: the key follows team.json. It comes back when team.json came back
        (take_back says so) or was never written, and it stays when the claim's commit did reach the ref, because
        that write is whole. And a second claim of a hub that had no key leaves no key when it fails."""
        with self.claimed("100.64.0.4", sha(KEY)):
            hubsetup.cmd_claim(self.args())
        path, team = Path(hubsetup.owner_key_file(self.db)), Path(self.out).read_text()
        found = path.read_bytes()

        def refused(*_args, **_named):
            raise hubsetup.Stop("the push was refused")

        def full(*_args):
            raise OSError("the disk is full")

        def fails(key, back, write=None):
            Path(self.out).write_text(team)                     # the hub of the first owner, each time
            with self.claimed("100.64.0.5", key), patch.object(hubsetup, "commit_team", refused), \
                    patch.object(hubsetup, "git", lambda *a, **k: (0, "0" * 40, "")), \
                    patch.object(hubsetup, "take_back", lambda *_a: back), \
                    patch.object(hubsetup, "write_team", write or hubsetup.write_team), \
                    self.assertRaises((hubsetup.Stop, OSError)):
                hubsetup.cmd_claim(self.args(reclaim=True, commit=True))
            self.assertEqual([p.name for p in path.parent.iterdir() if p.name != path.name], [])
        fails(sha(OTHER_KEY), back=True)                        # team.json came back: so does the key
        self.assertEqual(path.read_bytes(), found)
        fails(sha(OTHER_KEY), back=False)                       # the claim's commit reached the ref: its key stays
        self.assertEqual(json.loads(path.read_text())["sha256"], sha(OTHER_KEY))
        path.write_bytes(found)
        fails(sha(OTHER_KEY), back=False, write=full)           # team.json was never written, whatever take_back says
        self.assertEqual(path.read_bytes(), found)
        fails(None, back=False, write=full)                     # a claim with no key changed nothing of the key
        self.assertEqual(path.read_bytes(), found)
        fails(None, back=True)
        self.assertEqual(path.read_bytes(), found)
        path.unlink()                                           # a hub from before the key, with its owner
        fails(sha(OTHER_KEY), back=True)
        self.assertFalse(path.exists())

    def test_a_run_on_a_hub_that_has_its_owner_changes_no_key(self):
        with self.claimed("100.64.0.4", sha(KEY)):
            hubsetup.cmd_claim(self.args())
        with patch.object(hubsetup, "claim", lambda *a, **k: self.fail("it made a second claim")):
            hubsetup.cmd_claim(self.args())
        self.assertEqual(json.loads(Path(hubsetup.owner_key_file(self.db)).read_text())["sha256"], sha(KEY))

    def test_a_claim_that_names_no_records_touches_no_key_file(self):
        """A caller's own arguments with no `db` (the older tests of the claim) write nothing beside any records, and
        so nothing in the home folder of the machine that runs them."""
        args = self.args()
        del type(args).db
        with self.claimed("100.64.0.4", sha(KEY)), patch.object(hubsetup, "keep_owner_key") as keep:
            hubsetup.cmd_claim(args)
        keep.assert_not_called()

    def test_a_key_that_cannot_be_kept_stops_the_claim_before_it_names_an_owner(self):
        """So the next run of the installer makes a new claim, and not "this hub belongs to the Mac already" with no
        key."""
        Path(self.tmp / "records").write_text("a file where the folder must be")
        with self.claimed("100.64.0.4", sha(KEY)), self.assertRaises(hubsetup.Stop) as stopped:
            hubsetup.cmd_claim(self.args())
        self.assertIn("could not be kept", str(stopped.exception))
        self.assertIn("no owner yet", str(stopped.exception))
        self.assertFalse(os.path.exists(self.out))
        self.assertIsNone(hubsetup.claimed_by(self.out, HUB_IP, 8765))


class Listener(http.server.BaseHTTPRequestHandler):
    """A stand-in for the claim's listener and for the hub that follows it on the same port: POST /claim takes any
    code and keeps the SHA-256, and GET /ui/state answers 200 to the bearer whose SHA-256 that is, or, on a listener
    from before the key, to a call with no bearer."""
    protocol_version = "HTTP/1.0"

    def log_message(self, *_args):
        return

    def answer(self, status, headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        seen = self.server.seen
        seen["code"] = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()
        seen["sha"] = self.headers.get(hubsetup.OWNER_KEY_HEADER)
        seen["line"] = self.requestline
        seen.setdefault("shas", []).append(seen["sha"])
        if getattr(self.server, "loses", 0):            # the claim is taken, and its answer does not arrive
            self.server.loses -= 1
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        self.answer(200, ((hubsetup.OWNER_KEY_KEPT, "kept"),) if self.server.keeps else ())

    def do_GET(self):
        seen, sent = self.server.seen, self.headers.get("Authorization")
        seen.setdefault("reads", []).append(sent)
        if self.server.keeps:
            ok = sent is not None and sent.startswith("Bearer ") and sha(sent[7:]) == seen.get("sha")
        else:
            ok = sent is None
        self.answer(200 if ok else 403)


@unittest.skipUnless(shutil.which("curl") and shutil.which("sh"), "the claim's script needs sh and curl")
class ClaimScript(unittest.TestCase):
    """The line that the installer prints for Terminal, run as it is, with a home folder of this test."""

    def run_script(self, keeps, loses=0, runs=1, path=None, waits=None):
        """waits: what a file of the key that waits holds before the line runs."""
        home = Path(tempfile.mkdtemp(prefix="fleet-claim-home-"))
        self.addCleanup(shutil.rmtree, str(home), True)
        server = http.server.HTTPServer(("127.0.0.1", 0), Listener)
        server.seen, server.keeps, server.loses = {}, keeps, loses
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        if waits is not None:
            (home / ".founderizer" / "owner-keys").mkdir(parents=True, mode=0o700)
            (home / ".founderizer" / "owner-keys" / f"127.0.0.1_{port}.pending").write_text(waits)
        env = {"HOME": str(home), "PATH": path or os.environ.get("PATH", ""), "FLEET_CLAIM": SHOWN, "no_proxy": "*",
               "NO_PROXY": "*"}
        for _ in range(runs):
            done = subprocess.run([shutil.which("sh"), "-c", hubsetup.claim_script("127.0.0.1", port)], env=env,
                                  capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
        return home, port, server.seen, done

    def test_a_claim_whose_answer_was_lost_keeps_its_key_and_the_next_claim_sends_the_same_one(self):
        """The listener holds the SHA-256 of the first call. A second run of the line must not make a new key: the
        key that waits goes again, and it is this Mac's key when a claim's answer arrives."""
        home, port, seen, done = self.run_script(keeps=True, loses=1)
        self.assertNotEqual(done.returncode, 0)
        folder = home / ".founderizer" / "owner-keys"
        self.assertEqual([p.name for p in folder.iterdir()], [f"127.0.0.1_{port}.pending"])
        waits = (folder / f"127.0.0.1_{port}.pending").read_text().strip()
        self.assertEqual(seen["shas"], [sha(waits)])
        self.assertEqual(stat.S_IMODE((folder / f"127.0.0.1_{port}.pending").stat().st_mode), 0o600)
        home, port, seen, done = self.run_script(keeps=True, loses=1, runs=2)
        self.assertEqual(done.returncode, 0, done.stderr)
        key = (home / ".founderizer" / "owner-keys" / f"127.0.0.1_{port}").read_text().strip()
        self.assertEqual(seen["shas"], [sha(key)] * 2)                 # the same key both times
        self.assertEqual([p.name for p in (home / ".founderizer" / "owner-keys").iterdir()], [f"127.0.0.1_{port}"])

    def test_what_waits_and_is_no_whole_key_makes_way_for_a_new_key(self):
        """A write that broke off, or anything else in that file: with it sent again, or with the claim stopped for
        ever, this Mac could not claim a hub. Only a whole key goes again."""
        whole = "w" * 43
        for waits in ("", "short-key", "k" * 31, "k" * 200, "two words", KEY + "\n" + OTHER_KEY, "k" * 42 + "!"):
            home, port, seen, done = self.run_script(keeps=True, waits=waits)
            self.assertEqual(done.returncode, 0, (waits, done.stderr))
            key = (home / ".founderizer" / "owner-keys" / f"127.0.0.1_{port}").read_text().strip()
            self.assertRegex(key, r"^[A-Za-z0-9_-]{43}$", waits)
            self.assertNotIn(key, waits)
            self.assertEqual(seen["shas"], [sha(key)], waits)
            self.assertEqual([p.name for p in (home / ".founderizer" / "owner-keys").iterdir()], [f"127.0.0.1_{port}"])
        for whole in (whole, "k" * 32, "k" * 128):                      # 32 to 128 letters, as the other programs read one
            home, port, seen, done = self.run_script(keeps=True, waits=whole + "\n")
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(seen["shas"], [sha(whole)])                # a whole key that waits goes again
            self.assertEqual((home / ".founderizer" / "owner-keys" / f"127.0.0.1_{port}").read_text().strip(), whole)

    def test_a_mac_that_cannot_make_a_key_sends_nothing(self):
        """With no `base64` the key would be empty: its SHA-256 would be the one of no text, which everybody knows."""
        tools = Path(tempfile.mkdtemp(prefix="fleet-claim-tools-"))
        self.addCleanup(shutil.rmtree, str(tools), True)
        for tool in ("sh", "head", "tr", "curl", "mkdir", "chmod", "cat", "grep", "mv", "rm", "sleep", "shasum",
                     "sha256sum"):
            if shutil.which(tool):
                os.symlink(shutil.which(tool), tools / tool)
        home, port, seen, done = self.run_script(keeps=True, path=str(tools))
        self.assertEqual(done.returncode, 1)
        self.assertIn("could not make its key", done.stderr)
        self.assertEqual(seen, {})
        self.assertEqual(list((home / ".founderizer" / "owner-keys").iterdir()), [])

    def test_the_script_makes_the_key_keeps_it_for_this_user_and_sends_only_its_sha(self):
        home, port, seen, done = self.run_script(keeps=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(f"Paste this address in Founderizer: http://127.0.0.1:{port}", done.stdout)
        folder = home / ".founderizer" / "owner-keys"
        path = folder / f"127.0.0.1_{port}"
        key = path.read_text(encoding="utf-8").strip()
        self.assertRegex(key, r"^[A-Za-z0-9_-]{43}$")
        self.assertEqual(seen["sha"], sha(key))
        self.assertEqual(seen["code"], SHOWN)
        self.assertEqual(seen["reads"], ["Bearer " + key])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(folder.parent.stat().st_mode), 0o700)
        self.assertEqual(sorted(p.name for p in folder.iterdir()), [path.name])     # no file of the answer is left
        for said in (done.stdout, done.stderr, seen["line"]):
            self.assertNotIn(key, said)
            self.assertNotIn(SHOWN, said)

    def test_an_installer_from_before_the_key_leaves_no_key_and_gets_none(self):
        home, port, seen, done = self.run_script(keeps=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(seen["reads"], [None])
        folder = home / ".founderizer" / "owner-keys"
        self.assertEqual([p.name for p in folder.iterdir()], [])

    def test_the_key_is_in_no_argument_of_a_command(self):
        """A program's arguments show in the process list of the computer: the key goes to curl through its
        configuration on standard input, and its SHA-256, which is no secret, in a header."""
        script = hubsetup.claim_script(HUB_IP, 8765)
        for line in script.splitlines():
            if "curl" in line:
                self.assertNotRegex(line, r"curl[^|]*\$key")
                self.assertNotIn("$code", line.split("curl", 1)[1])
        self.assertIn("-K -", script)


class HubThatStarts(unittest.TestCase):
    """A real hub process: the folder of the key's file is set by hub.main() and by nothing else, so only a hub that
    starts shows that it reads the file which the claim wrote beside its records."""

    def hub(self, key=None):
        root = Path(tempfile.mkdtemp(prefix="fleet-owner-key-hub-"))
        self.addCleanup(shutil.rmtree, str(root), ignore_errors=True)
        (root / "team.json").write_text(json.dumps({
            "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2"},
            "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}))
        (root / "records").mkdir(mode=0o700)
        if key:         # as the claim writes it, before the hub's first start
            with patch.object(hubsetup, "say", lambda _words: None):
                hubsetup.keep_owner_key(str(root / "records" / "pilot.db"), sha(key))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        out = open(root / "out.txt", "w+")
        self.addCleanup(out.close)
        pipe, fds = parent_pipe(root)
        started = subprocess.Popen([sys.executable, "-m", "hub",
                                    "--host", "127.0.0.1", "--port", str(port), "--db", str(root / "records" / "pilot.db"),
                                    "--team", str(root / "team.json"), "--tick", "60", "--parent-pipe", str(pipe)],
                                   pass_fds=fds, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                   cwd=str(Path(hub.__file__).resolve().parent), env=dict(os.environ, HOME=str(root)))
        self.addCleanup(started.wait)
        self.addCleanup(started.terminate)
        base = f"http://127.0.0.1:{port}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(200):
            self.assertIsNone(started.poll(), f"the hub did not start: {(root / 'out.txt').read_text()}")
            try:
                with opener.open(base + "/health", timeout=5):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            self.fail(f"the hub never answered /health: {(root / 'out.txt').read_text()}")
        return base, root

    def read(self, base, path="/ui/state", token=None):
        request = urllib.request.Request(base + path, headers={"Authorization": "Bearer " + token} if token else {})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as answer:
                return answer.status, json.load(answer)
        except urllib.error.HTTPError as answer:
            with answer:
                return answer.code, json.load(answer)

    def said(self, root):
        """What the hub printed at its start: the service's own output."""
        return (root / "out.txt").read_text()

    def test_a_hub_that_starts_asks_for_the_key_that_the_claim_wrote_beside_its_records(self):
        base, root = self.hub(KEY)
        status, said = self.read(base)
        self.assertEqual((status, said.get("auth")), (403, "owner_key_required"))
        self.assertEqual(self.read(base, token=OTHER_KEY)[1].get("auth"), "owner_key_mismatch")
        status, said = self.read(base, token=KEY)
        self.assertEqual(status, 200)
        self.assertIn("owner_key", said["ui_features"])
        self.assertNotIn("holds no key of the owner's computer", self.said(root))

    def test_a_hub_that_starts_with_no_key_says_so_at_its_start(self):
        """A file that is gone takes the key with it, and nothing on a screen says so: the output of each start does,
        which the service's journal keeps."""
        base, root = self.hub()
        self.assertEqual(self.read(base)[0], 200)
        self.assertEqual(self.read(base, token=KEY)[1].get("auth"), "key_not_expected")
        self.assertIn("holds no key of the owner's computer", self.said(root))
        self.assertIn("sh hub.sh --reclaim", self.said(root))


if __name__ == "__main__":
    unittest.main()

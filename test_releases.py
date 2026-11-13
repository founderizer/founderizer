"""The release channel (PRODUCT.md 4.2 and 4.3, package P6): a fleet takes a signed release on one click, and a
bad release leaves it exactly where it was.

Nothing here reaches the network and nothing touches a real fleet: the channel is a stand-in that answers from a
table, the repositories are temporary ones made in setUp, and `selftest.py` and `fleet.py verify` are answered
from a table too, because the real pair takes minutes and reads the machine it runs on. Git is real throughout,
because the merge, the roll-back and the push are the whole point.

What it proves, in the order of the package's own check:

  - a good release is merged, checked and published, and this fleet moves onto it;
  - a release that breaks either check leaves the fleet at the pinned revision, with nothing on the ref;
  - a manifest with no signature, a wrong signature, or one character changed after signing is not acted on;
  - a held release is never applied, with automatic updates on;
  - an expired entitlement changes nothing in the hub: it is carried, shown, and acted on by nobody;
  - a fleet with no entitlement takes each release by itself too, with no Authorization header, when its hub runs
    as hub.sh installs it, on the configuration ref; a test's or a scratch hub with no entitlement never asks; a
    fleet with one asks as before;
  - a key can be replaced: every key of the key file is trusted, and a rotation strands no fleet;
  - an entitlement is checked with the entitlement key and a release with the release key, never the other way.
"""
import base64
import binascii
import contextlib
import functools
import hashlib
import inspect
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import hub
import releases
from test_ui_api import OwnerAPI

# The signing key of these tests. The real one lives only on the website host (4.2) and no hub ever holds one, so
# every test that needs a release makes its own key pair here and ships the public half in its own checkout.
SEED = bytes(range(32))
OTHER_SEED = bytes(range(32, 64))
NEXT_SEED = bytes(range(64, 96))        # the key that replaces SEED in a rotation (PRODUCT.md 4.3)
PLAN_SEED = bytes(range(96, 128))       # the entitlement key, which is not the release key (PRODUCT.md 4.2)
KEY = releases.public_key(SEED)
NEXT_KEY = releases.public_key(NEXT_SEED)
PLAN_KEY = releases.public_key(PLAN_SEED)

# selftest.py's own last line, as it reads on a healthy checkout: the five failures of COORDINATION.md rule 5 are
# the recorded baseline, so a release that fails exactly these passes the check.
WHOLE_OUT = "127 of 127 checks passed."           # it passes whole since 18 October 2026 (COORDINATION rule 5)
WHOLE_SCHEMA = "schema check: 0 steps refused."   # `hub.py --check-schema` on a database the release fits
HEALTHY_VERIFY = json.dumps([{"check": "disk", "state": "ok", "says": "40 GiB free", "fix": None},
                             {"check": "version", "state": "warn", "says": "not on config", "fix": None}])

TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}}}
PROFILE = "# Profile: vps\n\n**Character.** Careful.\n"


def load_tests(loader, _tests, _pattern):
    """Only the tests of this file: the fixture it borrows carries its own."""
    suite = unittest.TestSuite()
    for cls in (Signature, Manifest, Entitlement, Channel, Updates, HubRoutes, HubUpdates):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def git(*args, cwd=None, check=True):
    done = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main",
                           *args], cwd=cwd, capture_output=True, text=True, timeout=120)
    if check and done.returncode:
        raise AssertionError(f"git {' '.join(args)}: {done.stderr}")
    return done.stdout.strip()


def manifest(revision, version="2026.10.2", *, notes=None, minimum=None, hold=False, seed=SEED, signature=None):
    """One manifest of 4.3, signed as the website signs it."""
    body = {"revision": revision, "version": version, "notes": notes, "minimum": minimum, "hold": hold}
    signed = signature if signature is not None else \
        base64.b64encode(releases.sign(seed, releases.signed_text(body))).decode()
    return dict(body, signature=signed)


def channel_of(table):
    """A stand-in channel that answers by address: `latest`, and an older release by its revision. A release it does
    not hold is a 404, as the website answers it. `seen` is the addresses it was asked for."""
    seen = []

    def fetch(url, token=None, timeout=None):
        seen.append(url)
        body = table.get(url.rsplit("/", 1)[1])
        return (200, json.dumps(body), {}) if body else (404, json.dumps({"error": "no release"}), {})
    fetch.seen = seen
    return fetch


def answers(body, status=200, headers=None):
    """A stand-in for GET /releases/latest: what it answered, and the requests it was given."""
    seen = []

    def fetch(url, token=None, timeout=None):
        seen.append({"url": url, "token": token, "timeout": timeout})
        text = body if isinstance(body, str) else json.dumps(body)
        return status, text, headers or {}
    fetch.seen = seen
    return fetch


# ---------------------------------------------------------------- the signature

class Signature(unittest.TestCase):
    """Ed25519 as RFC 8032 defines it. The hub carries no dependency, so this is our own code and must be measured
    against the RFC's own vectors, not against itself."""

    VECTORS = [("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
               ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
               ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")]

    def test_the_rfc_8032_vectors_pass(self):
        for seed, public, message, signature in self.VECTORS:
            seed, public, message, signature = (binascii.unhexlify(x) for x in (seed, public, message, signature))
            self.assertEqual(releases.public_key(seed), public)
            self.assertEqual(releases.sign(seed, message), signature)
            self.assertTrue(releases.verify_signature(public, message, signature))

    def test_a_changed_message_or_key_does_not_verify(self):
        signature = releases.sign(SEED, b"a release")
        self.assertTrue(releases.verify_signature(KEY, b"a release", signature))
        self.assertFalse(releases.verify_signature(KEY, b"a release ", signature))
        self.assertFalse(releases.verify_signature(releases.public_key(OTHER_SEED), b"a release", signature))
        self.assertFalse(releases.verify_signature(KEY, b"a release", releases.sign(OTHER_SEED, b"a release")))

    def test_every_wrong_shape_is_false_and_never_an_error(self):
        """A manifest comes from outside this fleet, so a check of it must not be able to raise."""
        small = b"\x00" * 31 + b"\x80"       # a point of order two, whose own signatures verify in a careless check
        for public, message, signature in [(b"", b"x", b"y"), (KEY, b"x", b"short"), (b"\x00" * 32, b"x", b"\x00" * 64),
                                           (KEY, "text", b"\x00" * 64), (None, b"x", b"\x00" * 64),
                                           (KEY, b"x", b"\xff" * 64), (small, b"x", b"\x00" * 64),
                                           (b"\x01" + b"\x00" * 31, b"x", b"\x00" * 64)]:
            self.assertIs(releases.verify_signature(public, message, signature), False, (public, signature[:4]))
        for message in (b"", b"x", b"a release nobody signed"):
            self.assertIs(releases.verify_signature(b"\x00" * 32, message, b"\x00" * 64), False, message)


# ---------------------------------------------------------------- the manifest and the key file

class Manifest(unittest.TestCase):
    def setUp(self):
        self.kit = Path(tempfile.mkdtemp(prefix="fleet-release-key-"))
        self.addCleanup(shutil.rmtree, str(self.kit), True)

    def key_file(self, text):
        (self.kit / releases.KEY_FILE).write_text(text)
        return releases.read_keys(str(self.kit))

    def test_the_key_file_is_read_as_a_set_and_what_it_cannot_read_whole_carries_nothing(self):
        """Every key in the file is trusted, so the file is read as a set in its own order. A file with one line
        it cannot read carries nothing at all: a key file that is half read is a mistake, and a fleet that cannot
        say which keys it trusts takes no release."""
        self.assertEqual(releases.read_keys(str(self.kit)), ())         # no file at all
        one, next_one = base64.b64encode(KEY).decode(), base64.b64encode(NEXT_KEY).decode()
        self.assertEqual(self.key_file("# a comment\n" + one + "\n"), (KEY,))
        self.assertEqual(self.key_file(f"# the key that signs now\n{one}\n# the next one\n{next_one}\n"),
                         (KEY, NEXT_KEY))
        self.assertEqual(self.key_file("\n".join([one] * releases.MAX_KEYS)), (KEY,) * releases.MAX_KEYS)
        for wrong in ("", "# only comments\n", "not base64 at all\n", base64.b64encode(b"short").decode(),
                      f"{one}\nnot base64 at all\n",                        # one bad line, and nothing is trusted
                      f"{one}\n{base64.b64encode(b'short').decode()}\n",
                      "\n".join([one] * (releases.MAX_KEYS + 1))):           # more keys than a rotation needs
            self.assertEqual(self.key_file(wrong), (), wrong[:20])

    def test_the_keys_shipped_in_this_repository_are_the_ones_the_hub_would_use(self):
        """Today it carries none, so every manifest is refused until P7 publishes the first ones. If keys are ever
        committed here, each must be a 32-byte Ed25519 key and not something that only looks like one."""
        here = releases.read_keys(str(Path(__file__).resolve().parent))
        self.assertTrue(all(isinstance(key, bytes) and len(key) == 32 for key in here), here)

    def test_a_manifest_is_read_field_by_field(self):
        good = manifest("a" * 40, notes="https://founderizer.com/releases/2026.10.2", minimum="b" * 40)
        self.assertEqual(releases.read_manifest(good)["revision"], "a" * 40)
        self.assertEqual(releases.read_manifest(manifest("a" * 40))["minimum"], None)
        for wrong, why in [({}, "revision"), ("text", "manifest"),
                           (manifest("a" * 39), "revision"), (manifest("A" * 40), "revision"),
                           (dict(manifest("a" * 40), version=""), "version"),
                           (dict(manifest("a" * 40), version="x" * 60), "version"),
                           (dict(manifest("a" * 40), notes="http://founderizer.com/x"), "notes"),
                           (dict(manifest("a" * 40), minimum="zz"), "minimum"),
                           (dict(manifest("a" * 40), hold="yes"), "hold"),
                           (dict(manifest("a" * 40), signature=None), "signature")]:
            with self.assertRaises(releases.Untrusted, msg=why) as caught:
                releases.read_manifest(wrong)
            self.assertIn(why, str(caught.exception))

    def test_only_this_key_s_signature_of_this_manifest_is_acted_on(self):
        good = manifest("a" * 40, minimum="b" * 40, notes="https://founderizer.com/n")
        self.assertEqual(releases.check(good, KEY)["version"], "2026.10.2")
        for changed, why in [(dict(good, revision="c" * 40), "signature"),
                             (dict(good, version="2026.10.3"), "signature"),
                             (dict(good, notes="https://evil.example/n"), "signature"),
                             (dict(good, minimum=None), "signature"),
                             (dict(good, hold=True), "signature"),            # the hold cannot be stripped
                             (manifest("a" * 40, seed=OTHER_SEED), "signature"),
                             (manifest("a" * 40, signature="not base64!"), "base64")]:
            with self.assertRaises(releases.Untrusted, msg=why) as caught:
                releases.check(changed, KEY)
            self.assertIn(why, str(caught.exception))

    def test_a_fleet_with_no_release_key_acts_on_nothing(self):
        for carries in (None, (), [], (b"too short",)):
            with self.assertRaises(releases.Untrusted, msg=str(carries)) as caught:
                releases.check(manifest("a" * 40), carries)
            self.assertIn("no release key", str(caught.exception))

    def test_a_release_signed_by_any_key_of_the_file_is_taken_and_a_rotation_strands_nobody(self):
        """PRODUCT.md 4.3, "How a signing key is replaced". The release that brings the next key is signed with the
        key it replaces; every release after it is signed with the new one. A fleet that skipped the release in
        between carries only the old key, and the release it is offered next still carries both — so there is no
        release a fleet cannot check with a key it has. That only holds while every key in the file is trusted."""
        old, new = base64.b64encode(KEY).decode(), base64.b64encode(NEXT_KEY).decode()
        behind = self.key_file(old + "\n")                  # a fleet that never took the release with both keys
        both = self.key_file(f"{old}\n{new}\n")             # a fleet that took it
        ahead = self.key_file(new + "\n")                   # a fleet past the release that retired the old key
        for keys, seed, taken, who in [(behind, SEED, True, "behind, the old key signing"),
                                       (behind, NEXT_SEED, False, "behind, the new key signing"),
                                       (both, SEED, True, "both, the old key signing"),
                                       (both, NEXT_SEED, True, "both, the new key signing"),
                                       (ahead, NEXT_SEED, True, "ahead, the new key signing"),
                                       (ahead, SEED, False, "ahead, the retired key signing"),
                                       (both, OTHER_SEED, False, "both, a key that was never ours")]:
            raw = manifest("a" * 40, seed=seed)
            if taken:
                self.assertEqual(releases.check(raw, keys)["revision"], "a" * 40, who)
            else:
                with self.assertRaises(releases.Untrusted, msg=who) as caught:
                    releases.check(raw, keys)
                self.assertIn("signature", str(caught.exception))

    def test_a_later_signature_version_is_not_taken_by_this_one(self):
        """The signed bytes name their own version in the first line, so a fleet of this version refuses a manifest
        that a later signer signed differently instead of guessing at it."""
        body = {"revision": "a" * 40, "version": "2026.10.2", "notes": None, "minimum": None, "hold": False}
        later = releases.signed_text(body).replace(releases.SIGNED_PREFIX, b"founderizer-release-2")
        wrong = dict(body, signature=base64.b64encode(releases.sign(SEED, later)).decode())
        with self.assertRaises(releases.Untrusted):
            releases.check(wrong, KEY)


# ---------------------------------------------------------------- the entitlement

class Entitlement(unittest.TestCase):
    def token(self, seed=SEED, **change):
        claims = dict({"fleet": "0123456789abcdef", "plan": "monthly", "until": 2000000000,
                       "machines": 4, "agents": 6}, **change)
        return releases.sign_entitlement(seed, claims)

    def test_the_claims_are_read_and_our_signature_is_marked(self):
        read = releases.read_entitlement(self.token(), KEY)
        self.assertEqual((read["fleet"], read["plan"], read["machines"], read["agents"], read["verified"]),
                         ("0123456789abcdef", "monthly", 4, 6, True))
        self.assertFalse(releases.read_entitlement(self.token(seed=OTHER_SEED), KEY)["verified"])
        self.assertFalse(releases.read_entitlement(self.token(), None)["verified"])
        self.assertFalse(releases.read_entitlement(self.token(), ())["verified"])
        for signer in (SEED, NEXT_SEED):            # a key is replaced here as it is for a release (4.3)
            self.assertTrue(releases.read_entitlement(self.token(seed=signer), (KEY, NEXT_KEY))["verified"])
        self.assertFalse(releases.read_entitlement(self.token(seed=OTHER_SEED), (KEY, NEXT_KEY))["verified"])

    def test_an_expired_entitlement_is_read_exactly_like_a_live_one(self):
        """PRODUCT.md 4.2: nothing in the hub refuses work when it expires; only our side refuses. So this reader
        has no opinion about the date at all."""
        expired = releases.read_entitlement(self.token(until=1000000000), KEY)
        self.assertEqual(expired["until"], 1000000000)
        self.assertTrue(expired["verified"])

    def test_a_token_that_cannot_be_read_is_refused(self):
        for wrong in ["", "nodot", "a.b.c", "!!!.!!!", base64.urlsafe_b64encode(b"[]").decode() + ".x",
                      self.token(fleet="nothex"), self.token(plan=""), self.token(until=0),
                      self.token(machines="many")]:
            with self.assertRaises(releases.Untrusted, msg=wrong[:30]):
                releases.read_entitlement(wrong, KEY)

    def test_the_entitlement_key_is_read_from_its_own_file(self):
        """PRODUCT.md 4.2: the website signs a release with one key and an entitlement with the other. The two
        files are read apart, so neither can be given the other's work."""
        kit = Path(tempfile.mkdtemp(prefix="fleet-entitlement-key-"))
        self.addCleanup(shutil.rmtree, str(kit), True)
        (kit / releases.KEY_FILE).write_text(base64.b64encode(KEY).decode() + "\n")
        (kit / releases.ENTITLEMENT_KEY_FILE).write_text(base64.b64encode(PLAN_KEY).decode() + "\n")
        self.assertEqual(releases.read_keys(str(kit)), (KEY,))
        self.assertEqual(releases.read_keys(str(kit), releases.ENTITLEMENT_KEY_FILE), (PLAN_KEY,))
        plan = releases.read_keys(str(kit), releases.ENTITLEMENT_KEY_FILE)
        self.assertTrue(releases.read_entitlement(self.token(seed=PLAN_SEED), plan)["verified"])
        self.assertFalse(releases.read_entitlement(self.token(seed=SEED), plan)["verified"])
        (kit / releases.ENTITLEMENT_KEY_FILE).unlink()
        self.assertEqual(releases.read_keys(str(kit), releases.ENTITLEMENT_KEY_FILE), ())

    def test_the_entitlement_keys_shipped_in_this_repository_are_the_ones_the_hub_would_use(self):
        """It carries none today, exactly as the release key file does, so `verified` is false until P7 commits
        both. Any key ever committed here must be a 32-byte Ed25519 key."""
        here = releases.read_keys(str(Path(__file__).resolve().parent), releases.ENTITLEMENT_KEY_FILE)
        self.assertTrue(all(isinstance(key, bytes) and len(key) == 32 for key in here), here)

    def test_a_fleet_id_says_nothing_about_its_owner(self):
        made = {releases.new_fleet_id() for _ in range(20)}
        self.assertEqual(len(made), 20)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{16}", one) for one in made))


# ---------------------------------------------------------------- GET /releases/latest

class Channel(unittest.TestCase):
    def test_a_good_manifest_comes_back_with_the_entitlement_as_a_bearer(self):
        fetch = answers(manifest("a" * 40))
        answer = releases.latest("https://founderizer.com", KEY, "tok.en", fetch=fetch)
        self.assertEqual(answer["manifest"]["revision"], "a" * 40)
        self.assertIsNone(answer["says"])
        self.assertEqual(fetch.seen[0]["url"], "https://founderizer.com/releases/latest")
        self.assertEqual(fetch.seen[0]["token"], "tok.en")

    def test_a_fleet_with_no_entitlement_still_asks(self):
        fetch = answers(manifest("a" * 40))
        releases.latest("https://founderizer.com/", KEY, None, fetch=fetch)
        self.assertIsNone(fetch.seen[0]["token"])

    def test_one_release_is_asked_for_by_its_revision_and_no_other_is_taken(self):
        """The release that a newer one names as its minimum (hub.poll_release)."""
        fetch = answers(manifest("a" * 40))
        answer = releases.latest("https://founderizer.com", KEY, "tok.en", fetch=fetch, revision="a" * 40)
        self.assertEqual((answer["manifest"]["revision"], answer["says"]), ("a" * 40, None))
        self.assertEqual(fetch.seen[0]["url"], "https://founderizer.com/releases/" + "a" * 40)
        self.assertEqual(fetch.seen[0]["token"], "tok.en")
        other = releases.latest("https://founderizer.com", KEY, "tok.en", fetch=answers(manifest("a" * 40)),
                                revision="b" * 40)
        self.assertIsNone(other["manifest"])
        self.assertIn("another release than " + "b" * 12, other["says"])

    def test_a_fleet_that_takes_releases_early_asks_the_early_track(self):
        """PRODUCT.md 4.3 "Two tracks": the newest release, and one by its revision, each on the early track."""
        fetch = answers(manifest("a" * 40))
        releases.latest("https://founderizer.com", KEY, "tok.en", fetch=fetch, early=True)
        releases.latest("https://founderizer.com", KEY, "tok.en", fetch=fetch, revision="a" * 40, early=True)
        self.assertEqual([one["url"] for one in fetch.seen],
                         ["https://founderizer.com/releases/latest?track=early",
                          "https://founderizer.com/releases/" + "a" * 40 + "?track=early"])

    def test_what_it_cannot_check_or_read_gives_no_manifest_and_one_line(self):
        for body, status, why in [(manifest("a" * 40, seed=OTHER_SEED), 200, "signature"),
                                  (dict(manifest("a" * 40), signature=None), 200, "signature"),
                                  ("not json", 200, "JSON"),
                                  ({}, 401, "refused this fleet (401)"), ({}, 403, "refused this fleet (403)"),
                                  ({}, 500, "answered 500"), ("no route to host", 0, "did not answer")]:
            answer = releases.latest("https://founderizer.com", KEY, "t.k", fetch=answers(body, status))
            self.assertIsNone(answer["manifest"], why)
            self.assertIn(why, answer["says"])
            self.assertNotIn("subscription", answer["says"])
            self.assertNotIn("entitlement", answer["says"])

    def test_the_bearer_goes_on_the_wire_only_when_this_fleet_holds_an_entitlement(self):
        """The real request, not the stand-in: a fleet with no entitlement asks with no Authorization header and
        nothing else that names it (the website's docs/CONTRACTS.md, "A call with no token"), and gets the release.
        A fleet that holds one sends it as the bearer, as before Founderizer was free."""
        class OnTheWire(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
                out = json.dumps(manifest("a" * 40)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), OnTheWire)
        server.seen = []
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        channel = f"http://127.0.0.1:{server.server_port}"
        for token in (None, "tok.en"):
            answer = releases.latest(channel, KEY, token, early=True)
            self.assertEqual((answer["status"], answer["manifest"]["revision"], answer["says"]), (200, "a" * 40, None))
        (path, without), (_, with_token) = server.seen
        self.assertEqual(path, "/releases/latest?track=early")
        self.assertNotIn("authorization", without)
        self.assertLessEqual(set(without), {"accept", "accept-encoding", "connection", "host", "user-agent"})
        self.assertEqual(without["user-agent"], "founderizer-hub")
        self.assertEqual(with_token["authorization"], "Bearer tok.en")
        self.assertEqual({k: v for k, v in with_token.items() if k != "authorization"}, without)

    def test_a_fresh_entitlement_is_kept_whatever_the_manifest_did(self):
        """4.5: near expiry the hub asks for a fresh one with the old one, so the answer carries it."""
        fresh = releases.sign_entitlement(PLAN_SEED, {"fleet": "0" * 16, "plan": "monthly",
                                                      "until": 2000000000, "machines": 4, "agents": 6})
        for body in (dict(manifest("a" * 40), entitlement=fresh),
                     dict(manifest("a" * 40, seed=OTHER_SEED), entitlement=fresh)):
            answer = releases.latest("https://founderizer.com", KEY, "old.one", fetch=answers(body))
            self.assertEqual(answer["entitlement"], fresh)
        self.assertIsNone(releases.latest("https://founderizer.com", KEY, None,
                                          fetch=answers(dict(manifest("a" * 40), entitlement="nonsense")))["entitlement"])


# ---------------------------------------------------------------- the update, with real repositories

class Repositories(unittest.TestCase):
    """A fleet in the shape it runs in: `origin` carries the owner's configuration ref, `upstream` carries the
    published code, and the hub's checkout stands on the configuration ref with the owner's own commit on it."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-release-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "knowledge/owner").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (seed / "profiles/vps.md").write_text(PROFILE)
        (seed / "knowledge/owner/brand.md").write_text("# Brand\n\nBlue.\n")
        (seed / "hub.py").write_text("# the hub\nVERSION = 1\n")
        (seed / "RULES.md").write_text("# Rules\n")
        (seed / releases.KEY_FILE).write_text(base64.b64encode(KEY).decode() + "\n")
        (seed / releases.ENTITLEMENT_KEY_FILE).write_text(base64.b64encode(PLAN_KEY).decode() + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("branch", hub.CONFIG_BRANCH, cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", "--bare", str(seed), str(self.root / "upstream.git"))
        git("clone", "-q", "-b", hub.CONFIG_BRANCH, str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        self.origin, self.upstream = str(self.root / "origin.git"), str(self.root / "upstream.git")
        self.seeded = git("rev-parse", "HEAD", cwd=self.kit)
        self.owner_commit("knowledge/owner/brand.md", "# Brand\n\nBlue, and the owner's own.\n")
        self.pinned = git("rev-parse", "HEAD", cwd=self.kit)

    # ---- the three people who write to this repository

    def owner_commit(self, path, text):
        """What the hub commits for the owner on the configuration ref (`hub.commit_kit_file`)."""
        return self.ref_commit(path, text, "Owner changed " + path)

    def ref_commit(self, path, text, message):
        """One commit on the configuration ref, from this checkout, as the hub makes them: the owner's own file,
        or anything else that reaches that ref."""
        (self.kit / path).parent.mkdir(parents=True, exist_ok=True)
        (self.kit / path).write_text(text)
        git("add", "--", path, cwd=self.kit)
        git("commit", "-q", "-m", message, cwd=self.kit)
        git("push", "-q", "origin", "HEAD:" + hub.CONFIG_BRANCH, cwd=self.kit)
        return git("rev-parse", "HEAD", cwd=self.kit)

    def cut_write(self, *_):
        """A write of the hub's own whose push landed and whose fast-forward did not (hub.KIT_PUSHED): a team.json
        commit on the configuration ref that this checkout never took, so the rest of that write never ran."""
        work = self.root / ("cut-" + str(len(list(self.root.iterdir()))))
        git("clone", "-q", "-b", hub.CONFIG_BRANCH, self.origin, str(work))
        team = json.loads((work / "team.json").read_text())
        team["agents"]["vps"]["title"] = "The failed write"
        (work / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("commit", "-qam", "Owner changed the settings of vps", cwd=work)
        git("push", "-q", "origin", "HEAD:" + hub.CONFIG_BRANCH, cwd=work)
        return git("rev-parse", "HEAD", cwd=work)

    def publish(self, write, message="a release"):
        """What we push to the published repository: one commit of code, which becomes a release."""
        work = self.root / ("published-" + str(len(list(self.root.iterdir()))))
        git("clone", "-q", "-b", "main", self.upstream, str(work))
        write(work)
        git("add", "-A", cwd=work)
        git("commit", "-q", "-m", message, cwd=work)
        git("push", "-q", "origin", "HEAD:main", cwd=work)
        return git("rev-parse", "HEAD", cwd=work)

    @staticmethod
    def code(number):
        def write(work):
            (work / "hub.py").write_text(f"# the hub\nVERSION = {number}\n")
        return write

    # ---- the checks, answered from a table

    def runner(self, selftest=None, verify=None, schema=None):
        """Git for real; the three checks from a table, because `selftest.py` and `fleet.py verify` take minutes
        and read the machine they run on, and the schema check needs a real `hub.py` in the clone, which this
        fixture's two-line stand-in is not (`test_schema_guard.py` runs that one for real). Everything else is a
        mistake in the code under test."""
        selftest = selftest if selftest is not None else (0, WHOLE_OUT, "")
        verify = verify if verify is not None else (0, HEALTHY_VERIFY, "")
        schema = schema if schema is not None else (0, WHOLE_SCHEMA, "")
        self.ran = []

        def run(argv, timeout=None, cwd=None, input=None):
            self.ran.append(argv)
            if argv[0] == "git":
                return releases._run(argv, timeout=timeout or releases.GIT_WAIT, cwd=cwd, input=input)
            if argv[-1].endswith("selftest.py"):
                return selftest
            if argv[-2:] == ["verify", "--json"]:
                return verify
            if "--check-schema" in argv:
                return schema
            raise AssertionError("the update ran something unexpected: " + " ".join(argv))
        return run

    def runner_that(self, write, when="selftest.py"):
        """The runner above, with one commit pushed to the configuration ref while the update is at a step of its
        own: the hub writes that ref too (`hub.commit_kit_file`), and an update that takes minutes is written
        under. `write` is given how many commits it has made already and gives back the new revision."""
        inner = self.runner()
        self.wrote = []

        def run(argv, timeout=None, cwd=None, input=None):
            if when in " ".join(argv):
                self.wrote.append(write(len(self.wrote)))
            return inner(argv, timeout=timeout, cwd=cwd, input=input)
        return run

    def update(self, released, *, origin=None, run=None, **how):
        return releases.Update(str(self.kit), releases.check(manifest(released, **how), KEY), upstream=self.upstream,
                               origin=self.origin if origin is None else origin,
                               run=run or self.runner()).apply()

    # ---- what the fleet is standing on

    def ref(self, name, repository=None):
        return git("rev-parse", name, cwd=repository or self.origin)

    def head(self):
        return git("rev-parse", "HEAD", cwd=self.kit)

    def on_branch(self):
        return git("symbolic-ref", "--short", "HEAD", cwd=self.kit)

    def unchanged(self, answer):
        """The fleet is where it was: the checkout, its branch, and the configuration ref in origin."""
        self.assertEqual(self.head(), self.pinned, answer["says"])
        self.assertEqual(self.on_branch(), hub.CONFIG_BRANCH)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), self.pinned)
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 1\n")


class Updates(Repositories):
    def test_a_good_release_is_merged_checked_published_and_followed(self):
        released = self.publish(self.code(2), "Developer changed the hub")
        answer = self.update(released)
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        self.assertEqual(answer["pinned"], self.pinned)
        reached = answer["reached"]
        self.assertEqual(self.head(), reached)                       # this fleet moved
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), reached)       # and so did its configuration ref
        self.assertEqual(self.on_branch(), hub.CONFIG_BRANCH)
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")
        self.assertEqual(git("rev-parse", reached + "^1", cwd=self.kit), self.pinned)
        self.assertEqual(git("rev-parse", reached + "^2", cwd=self.kit), released)
        self.assertEqual(self.ref("main"), self.seeded)              # the code branch of origin is not touched
        self.assertIn("Blue, and the owner's own.", (self.kit / "knowledge/owner/brand.md").read_text())

    def test_a_release_that_fails_selftest_leaves_the_fleet_at_the_pinned_revision(self):
        released = self.publish(self.code(2))
        broken = ("125 of 127 checks passed. FAILED: ['manager has 13 tools', 'the new thing is broken']")
        # two names, and since the baseline is empty both of them are the release's own
        answer = self.update(released, run=self.runner(selftest=(1, broken, "")))
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "selftest"))
        self.assertIn("the new thing is broken", answer["says"])
        self.assertIn(self.pinned[:12], answer["says"])
        self.assertEqual(answer["pinned"], self.pinned)
        self.unchanged(answer)
        self.assertFalse(any("push" in argv for argv in self.ran), "nothing was pushed")

    def test_a_failure_the_baseline_used_to_excuse_is_a_broken_release_now(self):
        """COORDINATION.md rule 5 has no standing failure since 18 October 2026, and the baseline is read from
        verify.py so the release check and `fleet.py verify` cannot drift apart: a name it used to excuse is a
        release this fleet does not take."""
        import verify
        self.assertEqual(verify.SELFTEST_BASELINE, ())
        out = "126 of 127 checks passed. FAILED: ['worker has 8 tools']"
        answer = self.update(self.publish(self.code(2)), run=self.runner(selftest=(1, out, "")))
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "selftest"))
        self.assertIn("worker has 8 tools", answer["says"])
        self.unchanged(answer)

    def test_a_release_whose_selftest_says_nothing_is_not_taken(self):
        for said in [(0, "", "python3: command not found"), (0, "Traceback (most recent call last):", ""),
                     (1, "", "")]:
            self.setUp()
            answer = self.update(self.publish(self.code(2)), run=self.runner(selftest=said))
            self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "selftest"), said)
            self.unchanged(answer)

    def test_a_release_that_verify_calls_unhealthy_leaves_the_fleet_where_it_was(self):
        bad = json.dumps([{"check": "services", "state": "fail", "says": "fleet-hub is dead", "fix": "look"},
                          {"check": "disk", "state": "ok", "says": "fine", "fix": None}])
        answer = self.update(self.publish(self.code(2)), run=self.runner(verify=(1, bad, "")))
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "verify"))
        self.assertIn("services", answer["says"])
        self.unchanged(answer)

    def test_a_fleet_nobody_has_signed_in_yet_still_takes_the_release(self):
        """`runtime_signed_in` is the owner's own step in the app, and no release can pass it. A new fleet would
        otherwise be held at the revision it was installed with for ever, including the release that fixes the
        sign-in itself (18 October 2026)."""
        waiting = json.dumps([{"check": "runtime_signed_in", "state": "fail",
                               "says": "manager is not signed in to claude", "fix": "sign in from the app"},
                              {"check": "services", "state": "ok", "says": "all active", "fix": None}])
        answer = self.update(self.publish(self.code(2)), run=self.runner(verify=(1, waiting, "")))
        self.assertEqual(answer["state"], releases.DONE, answer["says"])

    def test_a_verify_that_answers_nothing_readable_leaves_the_fleet_where_it_was(self):
        answer = self.update(self.publish(self.code(2)), run=self.runner(verify=(0, "NOT READY", "")))
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "verify"))
        self.unchanged(answer)

    def test_a_held_release_is_never_applied_and_the_fleet_is_not_even_fetched(self):
        released = self.publish(self.code(2))
        answer = self.update(released, hold=True)
        self.assertEqual((answer["state"], answer["step"]), (releases.KEPT, "hold"))
        self.assertIn("is held", answer["says"])
        self.unchanged(answer)
        self.assertEqual(self.ran, [])
        self.assertEqual(git("remote", cwd=self.kit), "origin")      # the remote was not even added

    def test_code_that_reached_the_ref_without_a_release_does_not_survive_one(self):
        """DevOps plan 0.1: a release takes its own tree outside the fleet's data, so a line of code that reached the
        configuration ref without a release is replaced by the release's, and every machine can then prove that what
        it takes is the signed revision's own (lifecycle.may_take). There is nothing left to conflict."""
        self.owner_commit("hub.py", "# the hub\nVERSION = 'this fleet changed this line'\n")
        self.pinned = self.head()
        released = self.publish(self.code(2))
        answer = self.update(released)
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")
        self.assertEqual(git("diff", "--name-only", released, "HEAD", cwd=self.kit).split(),
                         ["knowledge/owner/brand.md", "release.json"])
        self.assertEqual(git("status", "--porcelain", cwd=self.kit), "")

    def test_the_signed_manifest_is_on_the_ref_and_every_machine_may_take_it(self):
        """The commit that a release puts on the ref carries the manifest the hub checked, field for field, and it
        is exactly what `lifecycle.may_take` lets a machine move onto: the signature, a revision that descends from
        the one it runs, and that revision's own tree outside the data."""
        import lifecycle
        released = self.publish(self.code(2))
        answer = self.update(released)
        self.assertEqual(answer["state"], releases.DONE, answer["says"])
        kept = json.loads((self.kit / lifecycle.RELEASE_FILE).read_text())
        self.assertEqual(releases.check(kept, KEY), releases.check(manifest(released), KEY))
        self.assertIsNone(lifecycle.may_take(str(self.kit), answer["reached"], head=self.pinned))
        self.assertIsNone(lifecycle.may_take(str(self.kit), "HEAD", head=self.pinned))

    def test_a_release_the_check_of_each_machine_refuses_is_never_pushed(self):
        """The hub runs the machines' own check on what it would push: a release under the hub user's floor (an older
        one than this fleet took) passes every other check and is still never put on the ref, where no machine could
        take it."""
        import lifecycle
        self.assertEqual(self.update(self.publish(self.code(2), "the release this fleet runs"))["state"], releases.DONE)
        self.pinned = self.head()
        older = self.publish(self.code(3), "the older release")
        newer = self.publish(self.code(4), "the newer release")
        floor = self.root / "floor"
        floor.write_text(json.dumps({"revision": newer, "version": "2026.10.3"}) + "\n")
        answer = releases.Update(str(self.kit), releases.check(manifest(older), KEY), upstream=self.upstream,
                                 origin=self.origin, run=self.runner(), floor=str(floor)).apply()
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "take"), answer["says"])
        self.assertIn("does not descend from the newest release", answer["says"])
        self.assertEqual(self.head(), self.pinned)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), self.pinned)
        self.assertFalse(any("push" in argv for argv in self.ran), "nothing was pushed")
        self.assertEqual(lifecycle.read_floor(str(floor)), (newer, None))

    def test_a_release_never_moves_the_owner_s_own_files(self):
        """The published repository carries a team.json, profiles and owner knowledge of its own. Taking them would
        replace the fleet that the release was meant to update, so they come back as the pinned revision has
        them, inside the merge commit."""
        def ours(work):
            (work / "hub.py").write_text("# the hub\nVERSION = 2\n")
            (work / "team.json").write_text(json.dumps({"agents": {"ours": {}}}) + "\n")
            (work / "profiles/vps.md").write_text("# Profile: somebody else's vps\n")
            (work / "knowledge/owner/brand.md").write_text("# Brand\n\nOurs, not the customer's.\n")
            (work / "profiles/stranger.md").write_text("# Profile: a stranger\n")
        answer = self.update(self.publish(ours, "a release that also carries our own configuration"))
        self.assertEqual(answer["state"], releases.DONE, answer["says"])
        self.assertEqual(json.loads((self.kit / "team.json").read_text()), TEAM)
        self.assertEqual((self.kit / "profiles/vps.md").read_text(), PROFILE)
        self.assertIn("Blue, and the owner's own.", (self.kit / "knowledge/owner/brand.md").read_text())
        self.assertFalse((self.kit / "profiles/stranger.md").exists())
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")      # the code did arrive
        self.assertEqual(git("diff", "--name-only", self.pinned, "HEAD", cwd=self.kit).split(),
                         ["hub.py", "release.json"])

    def test_a_release_the_fleet_already_runs_is_not_applied_again(self):
        released = self.publish(self.code(2))
        self.assertEqual(self.update(released)["state"], releases.DONE)
        self.pinned = self.head()
        answer = self.update(released)
        self.assertEqual((answer["state"], answer["step"]), (releases.KEPT, "already"))
        self.assertEqual(self.head(), self.pinned)

    def test_a_fleet_older_than_the_release_s_minimum_is_not_updated(self):
        step = self.publish(self.code(2), "the release in between")
        released = self.publish(self.code(3))
        answer = self.update(released, minimum=step)
        self.assertEqual((answer["state"], answer["step"]), (releases.KEPT, "minimum"))
        self.assertIn(step[:12], answer["says"])
        self.unchanged(answer)
        self.assertEqual(self.update(released, minimum=self.pinned)["state"], releases.DONE)

    def test_a_revision_that_is_not_in_the_published_repository_is_not_invented(self):
        answer = self.update("a" * 40)
        self.assertEqual((answer["state"], answer["step"]), (releases.KEPT, "have"))
        self.unchanged(answer)

    def test_a_checkout_with_its_own_changes_or_off_the_ref_is_left_alone(self):
        (self.kit / "hub.py").write_text("# somebody is working in here\n")
        answer = self.update(self.publish(self.code(2)))
        self.assertEqual((answer["state"], answer["step"]), (releases.KEPT, "clean"))
        self.assertEqual(self.head(), self.pinned)
        git("checkout", "-q", "--", "hub.py", cwd=self.kit)
        git("checkout", "-q", "--detach", cwd=self.kit)
        answer = self.update(self.publish(self.code(3)))
        self.assertEqual((answer["state"], answer["step"]), (releases.KEPT, "branch"))

    def test_a_push_that_is_refused_leaves_the_fleet_where_it_was(self):
        """Both checks passed, and the ref moved under us meanwhile: nothing has left the clone, so the fleet is
        simply still where it was and the owner is told."""
        released = self.publish(self.code(2))
        answer = self.update(released, origin=str(self.root / "nowhere.git"))
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "push"))
        self.unchanged(answer)

    def test_a_hub_commit_while_the_checks_run_does_not_cost_the_release(self):
        """The race the owner's own fleet met on 19 October 2026. The hub commits the owner's own file to the
        configuration ref while `selftest.py` is running, so the push of a release that passed every check is
        refused as a non-fast-forward. The release is merged onto the ref's new tip and taken: no second run, no
        second check, and nothing for the owner to do."""
        released = self.publish(self.code(2), "Developer changed the hub")
        run = self.runner_that(lambda n: self.owner_commit("profiles/vps.md", PROFILE + "\n**Very careful.**\n"))
        answer = self.update(released, run=run)
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        reached = answer["reached"]
        self.assertEqual(answer["pinned"], self.pinned)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), reached)          # the release is on the ref
        self.assertEqual(self.head(), reached)                          # and this fleet moved onto it
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")    # the released code
        self.assertIn("**Very careful.**", (self.kit / "profiles/vps.md").read_text())      # and the owner's own
        self.assertIn(self.wrote[0], git("rev-list", reached, cwd=self.kit).split("\n"))
        checks = [argv for argv in self.ran if argv[-1].endswith("selftest.py")]
        self.assertEqual(len(checks), 1, "the checks are not run again for the owner's own files")

    def test_a_skill_an_agent_writes_while_the_checks_run_does_not_cost_the_release(self):
        """Design v4 D1: skills/ is the fleet's own (lifecycle.data_path), so a skill that the hub commits for an agent
        while a release is checked is taken along as the owner's profile is, and a script in it is no code that
        the checks would have to read again."""
        released = self.publish(self.code(2), "Developer changed the hub")
        run = self.runner_that(lambda n: self.ref_commit("skills/vps/deploy/check.py", "print('smoke')\n",
                                                         "vps wrote the skill deploy"))
        answer = self.update(released, run=run)
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")
        self.assertEqual((self.kit / "skills/vps/deploy/check.py").read_text(), "print('smoke')\n")
        self.assertEqual(len([argv for argv in self.ran if argv[-1].endswith("selftest.py")]), 1)

    def test_a_write_of_the_hub_s_own_cut_off_while_the_checks_run_is_not_followed(self):
        """The hub's push of the owner's team.json landed while `selftest.py` ran, and its own fast-forward did not,
        so the rest of that write never ran and the hub takes it back (hub.KIT_PUSHED, `own`). A merge onto it would
        carry it in: the run ends rolled back at the push instead, and the next run takes the release."""
        released = self.publish(self.code(2), "Developer changed the hub")
        run = self.runner_that(self.cut_write)
        answer = releases.Update(str(self.kit), releases.check(manifest(released), KEY), upstream=self.upstream,
                                 origin=self.origin, run=run, own=lambda tip: tip in self.wrote).apply()
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "push"), answer["says"])
        self.assertEqual((self.ref(hub.CONFIG_BRANCH), self.head()), (self.wrote[0], self.pinned))
        self.assertIsNone(answer["reached"])

    def test_a_release_never_moves_an_agent_s_skills(self):
        """A release that carries skills/ of its own brings none of it, and leaves the fleet's own as they are."""
        self.ref_commit("skills/vps/deploy/SKILL.md", "---\nname: deploy\n---\n\nThe fleet's own steps.\n",
                        "vps wrote the skill deploy")
        self.pinned = self.head()

        def ours(work):
            (work / "hub.py").write_text("# the hub\nVERSION = 2\n")
            (work / "skills/vps/deploy").mkdir(parents=True)
            (work / "skills/vps/deploy/SKILL.md").write_text("---\nname: deploy\n---\n\nOur steps.\n")
            (work / "skills/stranger/x").mkdir(parents=True)
            (work / "skills/stranger/x/SKILL.md").write_text("---\nname: x\n---\n\nA stranger's.\n")
        answer = self.update(self.publish(ours, "a release that also carries skills"))
        self.assertEqual(answer["state"], releases.DONE, answer["says"])
        self.assertIn("The fleet's own steps.", (self.kit / "skills/vps/deploy/SKILL.md").read_text())
        self.assertFalse((self.kit / "skills/stranger").exists())
        self.assertEqual(git("diff", "--name-only", self.pinned, "HEAD", cwd=self.kit).split(),
                         ["hub.py", "release.json"])

    def test_code_that_reaches_the_ref_during_the_checks_is_replaced_by_the_checked_release(self):
        """The other half of following a moved ref. A commit that changes code while the checks run is followed, and
        its code does not survive: the merge onto the new tip takes every path but the data from the release, so the
        tree that is pushed is the tree the checks passed, file for file, and the checks do not run again."""
        released = self.publish(self.code(2))
        run = self.runner_that(lambda n: self.ref_commit("RULES.md", "# Rules\n\nAnd one more.\n",
                                                         "Somebody changed the rules"))
        answer = self.update(released, run=run)
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        self.assertIn(self.wrote[0], git("rev-list", answer["reached"], cwd=self.kit).split("\n"))
        self.assertEqual((self.kit / "RULES.md").read_text(), "# Rules\n")
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")
        self.assertEqual(len([argv for argv in self.ran if argv[-1].endswith("selftest.py")]), 1)

    def test_a_hand_change_of_the_same_file_as_the_release_is_no_conflict_either(self):
        """A conflict needs two sides that may both write a path, and only a release writes code: the hand change
        to hub.py that reached the ref meanwhile gives way to the released hub.py, and the release is taken."""
        released = self.publish(self.code(2))
        run = self.runner_that(lambda n: self.ref_commit("hub.py", "# the hub\nVERSION = 99\n",
                                                         "Somebody changed the hub by hand"))
        answer = self.update(released, run=run)
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), answer["reached"])
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")

    def test_a_ref_that_moves_under_every_push_gives_up_after_a_bounded_number_of_them(self):
        """Following the ref is bounded. A fleet that writes between every push and the next keeps its revision,
        with a line that says what it was, instead of a run that goes on for ever."""
        released = self.publish(self.code(2))
        run = self.runner_that(lambda n: self.owner_commit("knowledge/owner/brand.md", f"# Brand\n\n{n}\n"),
                               when="push")
        answer = self.update(released, run=run)
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "push"), answer["says"])
        self.assertIn(str(releases.PUSH_TRIES), answer["says"])
        self.assertEqual(len(self.wrote), releases.PUSH_TRIES)          # one commit for each push, and no more
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), self.wrote[-1])   # the owner's commits, and no release
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 1\n")

    def test_a_push_that_landed_and_then_failed_is_not_reported_as_a_roll_back(self):
        """Rule 9 of RULES.md, read for a program: the push is the step that leaves this machine, so what it did
        is read from the ref. A hook or a connection that fails after the ref moved would otherwise have the
        fleet say it kept its revision while every machine of it follows the new one."""
        released = self.publish(self.code(2))
        inner = self.runner()

        def run(argv, timeout=None, cwd=None, input=None):
            answer = inner(argv, timeout=timeout, cwd=cwd, input=input)
            if "push" in argv:                  # it moved the ref, and then git ended badly anyway
                return 1, "", "fatal: the remote end hung up unexpectedly"
            return answer
        answer = self.update(released, run=run)
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), answer["reached"])
        self.assertEqual(self.head(), answer["reached"])
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")

    def test_a_record_of_the_push_that_fails_does_not_stop_the_follow(self):
        """`pushed` only records what the answer carries too. An error in it (the hub's records locked for a moment)
        must not leave the release on the ref with this checkout behind it."""
        def pushed(merged):
            raise RuntimeError("database is locked")
        update = releases.Update(str(self.kit), releases.check(manifest(self.publish(self.code(2))), KEY),
                                 upstream=self.upstream, origin=self.origin, run=self.runner(), pushed=pushed)
        with patch.object(releases.traceback, "print_exc", lambda: None):
            answer = update.apply()
        self.assertEqual((answer["state"], answer["step"]), (releases.DONE, "follow"), answer["says"])
        self.assertEqual((self.ref(hub.CONFIG_BRANCH), self.head()), (answer["reached"], answer["reached"]))

    def test_a_fleet_with_no_address_for_its_ref_changes_nothing(self):
        answer = self.update(self.publish(self.code(2)), origin="")
        self.assertEqual((answer["state"], answer["step"]), (releases.ROLLED_BACK, "push"))
        self.unchanged(answer)

    def test_the_remote_upstream_is_added_once_and_pointed_at_the_published_repository(self):
        self.assertEqual(self.update(self.publish(self.code(2)))["state"], releases.DONE)
        self.assertEqual(git("remote", cwd=self.kit).split(), ["origin", releases.REMOTE])
        self.assertEqual(git("remote", "get-url", releases.REMOTE, cwd=self.kit), self.upstream)
        git("remote", "set-url", releases.REMOTE, "https://founderizer.invalid/moved.git", cwd=self.kit)
        self.pinned = self.head()
        self.assertEqual(self.update(self.publish(self.code(3)))["state"], releases.DONE)
        self.assertEqual(git("remote", "get-url", releases.REMOTE, cwd=self.kit), self.upstream)

    def test_every_answer_names_a_state_and_a_step_of_the_module(self):
        for answer in [self.update(self.publish(self.code(2)), hold=True),
                       self.update("a" * 40),
                       self.update(self.publish(self.code(3)))]:
            self.assertIn(answer["state"], releases.STATES)
            self.assertIn(answer["step"], releases.STEPS)
            self.assertTrue(answer["says"])


# ---------------------------------------------------------------- the hub's own state and routes

class HubRoutes(OwnerAPI):
    """The routes the app reads and presses. The channel is a stand-in, so no test reaches the network."""

    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.root = Path(tempfile.mkdtemp(prefix="fleet-release-hub-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        kit = self.root / "kit"
        kit.mkdir()
        (kit / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (kit / releases.KEY_FILE).write_text(base64.b64encode(KEY).decode() + "\n")
        (kit / releases.ENTITLEMENT_KEY_FILE).write_text(base64.b64encode(PLAN_KEY).decode() + "\n")
        git("init", "-q", "-b", hub.CONFIG_BRANCH, str(kit))
        git("add", "-A", cwd=kit)
        git("commit", "-q", "-m", "seed", cwd=kit)
        self.kit = kit
        hub.CFG["team_path"] = str(kit / "team.json")
        hub.CFG["release_channel"] = "https://channel.invalid"
        hub.CFG["hub_restart"] = []
        hub._revision_cache.update(at=0.0, value=None)
        hub._release["thread"] = None

    def tearDown(self):
        super().tearDown()
        for key in ("team_path", "release_channel", "release_upstream", "hub_restart"):
            hub.CFG.pop(key, None)
        hub._revision_cache.update(at=0.0, value=None)
        hub._release["thread"] = None

    # ---- helpers

    def releases_state(self):
        code, data = self.request("/ui/releases?db=test-generation")
        self.assertEqual(code, 200, data)
        return data

    def press(self, path, **body):
        return self.request("/ui/releases/" + path, self.command(**body))

    def channel(self, body, status=200):
        """The stand-in channel for one call, and the poll run to its end."""
        return patch.object(releases, "latest",
                            functools.partial(releases.latest, fetch=answers(body, status)))

    def token(self, seed=PLAN_SEED, **change):
        """An entitlement as the website issues one: signed with the entitlement key, not the release key (4.2)."""
        claims = dict({"fleet": hub.fleet_id(), "plan": "monthly", "until": 2000000000,
                       "machines": 4, "agents": 6}, **change)
        return releases.sign_entitlement(seed, claims)

    def finish(self):
        thread = hub._release["thread"]
        if thread is not None:
            thread.join(60)
            self.assertFalse(thread.is_alive(), "the release thread did not finish")

    def task_for(self, owner="vps"):
        """One task of this fleet, made the way the manager makes one: the row, its first attempt and the start
        event that its helper reads."""
        said = hub.t_create_task("manager", {"owner": owner, "title": "Read the practice page",
                                             "done_when": "the answer is in the result"})
        return int(said.split()[1][2:].rstrip("."))

    def starts(self, agent="vps"):
        """The task starts this agent's helper is given right now. A start that is held stays in the queue, so this
        is empty while it is held and names the task afterwards."""
        code, data = self.request(f"/events/{agent}?delivery=1&after=0&wait=0", source=hub.address_of(agent))
        self.assertEqual(code, 200, data)
        return [e["task"] for e in data["events"] if e["kind"] == "task"]

    # ---- the state

    def test_the_app_is_told_that_this_hub_has_releases_and_an_entitlement(self):
        features = self.request()[1]["ui_features"]
        self.assertIn("releases", features)
        self.assertIn("entitlement", features)

    def test_the_whole_state_is_one_read(self):
        state = self.releases_state()
        self.assertEqual(state["revision"], git("rev-parse", "HEAD", cwd=self.kit))
        self.assertEqual((state["branch"], state["channel"]), (hub.CONFIG_BRANCH, "https://channel.invalid"))
        self.assertEqual((state["automatic"], state["running"], state["idle"]), (True, False, True))
        self.assertTrue(state["have_release_key"])
        self.assertEqual(state["releases"], [])
        self.assertEqual(state["last_check"], {"at": None, "says": None, "status": None})
        self.assertFalse(state["entitlement"]["have_token"])
        self.assertEqual(state["upstream"], hub.release_upstream())

    def test_a_fleet_that_configured_nothing_asks_our_own_channel_and_repository(self):
        hub.CFG.pop("release_channel", None)
        self.assertEqual(hub.release_channel(), releases.DEFAULT_CHANNEL)
        self.assertEqual(hub.release_upstream(), releases.DEFAULT_UPSTREAM)
        hub.kv_set("release_channel", "https://another.invalid")
        self.assertEqual(hub.release_channel(), "https://another.invalid")
        hub.kv_set("release_channel", None)

    def test_a_fleet_with_an_open_task_is_not_idle(self):
        hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('t','vps','manager','working',?)",
                (hub.now(),))
        hub.touch("vps")        # plan P0: its helper is online and lists no window, so its turn may run
        state = self.releases_state()
        self.assertEqual((state["idle"], state["open_tasks"]), (False, [1]))

    def test_the_read_needs_this_hub_s_generation(self):
        self.assertEqual(self.request("/ui/releases?db=other")[0], 409)

    # ---- the poll

    def test_a_check_records_the_release_the_channel_offers(self):
        with self.channel(manifest("a" * 40, version="2026.10.3",
                                   notes="https://founderizer.com/releases/2026.10.3")):
            code, answer = self.press("check")
            self.assertEqual((code, answer["started"], answer["applying"]), (200, True, False))
            self.finish()
        state = self.releases_state()
        self.assertEqual(len(state["releases"]), 1)
        one = state["releases"][0]
        self.assertEqual((one["revision"], one["version"], one["state"], one["hold"], one["applied"]),
                         ("a" * 40, "2026.10.3", "verified", False, False))
        self.assertEqual(one["notes"], "https://founderizer.com/releases/2026.10.3")
        self.assertEqual(state["last_check"]["status"], 200)
        self.assertIsNone(state["last_check"]["says"])
        self.assertEqual(state["revision"], git("rev-parse", "HEAD", cwd=self.kit))      # and nothing moved

    def test_only_a_fleet_that_takes_releases_early_trusts_the_early_key(self):
        """PRODUCT.md 4.3 "Two tracks": the early key signs each release with no person there, so only a fleet whose
        setting releases.early is on asks the early track and trusts that key; every other fleet refuses it."""
        (self.kit / releases.EARLY_KEY_FILE).write_text(base64.b64encode(NEXT_KEY).decode() + "\n")
        early = manifest("a" * 40, seed=NEXT_SEED)
        for on in (False, True):
            hub.TEAM["settings"] = {"releases.early": on}
            fetch = answers(early)
            with patch.object(releases, "latest", functools.partial(releases.latest, fetch=fetch)):
                self.press("check")
                self.finish()
            state = self.releases_state()
            self.assertEqual(state["early"], on)
            self.assertEqual(fetch.seen[0]["url"].endswith("?track=early"), on)
            self.assertEqual([one["revision"] for one in state["releases"]], ["a" * 40] if on else [])

    def test_a_held_release_is_recorded_as_held(self):
        with self.channel(manifest("a" * 40, hold=True)):
            self.press("check")
            self.finish()
        self.assertEqual(self.releases_state()["releases"][0]["state"], "held")

    def test_a_manifest_this_fleet_cannot_check_is_not_recorded_at_all(self):
        """A manifest that does not verify is text from outside this fleet, so the hub keeps one line about it and
        nothing of its content."""
        for body, status, why in [(manifest("a" * 40, seed=OTHER_SEED), 200, "signature"),
                                  (dict(manifest("b" * 40), signature="bm9uc2Vuc2U="), 200, "signature"),
                                  ({}, 401, "refused this fleet"), ("down", 0, "did not answer")]:
            with self.channel(body, status):
                self.press("check")
                self.finish()
            state = self.releases_state()
            self.assertEqual(state["releases"], [], why)
            self.assertIn(why, state["last_check"]["says"])
            self.assertEqual(hub.q1("SELECT count(*) n FROM releases")["n"], 0)

    def test_two_runs_at_once_are_refused(self):
        started = threading.Event()

        def slow(*_a, **_k):
            started.wait(10)
            return {"status": 0, "manifest": None, "entitlement": None, "says": "the stand-in channel"}
        with patch.object(releases, "latest", slow):
            self.assertEqual(self.press("check")[0], 200)
            code, answer = self.press("check")
            self.assertEqual(code, 409, answer)
            self.assertIn("already checking", answer["error"])
            started.set()
            self.finish()

    def test_a_check_holds_no_work_because_it_publishes_nothing(self):
        """The hold belongs to the update, not to the channel: a check pushes nothing and restarts nothing, so a
        task that is created while one is going starts at once."""
        started, go = threading.Event(), threading.Event()

        def slow(*_a, **_k):
            started.set()
            go.wait(30)
            return {"status": 0, "manifest": None, "entitlement": None, "says": "the stand-in channel"}
        with patch.object(releases, "latest", slow):
            self.assertEqual(self.press("check")[0], 200)
            self.assertTrue(started.wait(30), "the check never reached the channel")
            tid = self.task_for()
            self.assertTrue(hub.release_running())
            self.assertFalse(hub.release_applying())
            self.assertEqual(self.starts(), [hub.tref(tid)])
            go.set()
            self.finish()

    # ---- automatic

    def swept(self, t0=None):
        """One automatic sweep, run to its end: what it asked the stand-in channel, as (address, token). The
        release that the channel offers is held, so a sweep that asks takes nothing and reaches no repository."""
        fetch = answers(manifest("a" * 40, hold=True))
        with patch.object(releases, "latest", functools.partial(releases.latest, fetch=fetch)):
            hub.release_sweep(t0 or hub.now())
            self.finish()
        return [(one["url"], one["token"]) for one in fetch.seen]

    @contextlib.contextmanager
    def installed(self):
        """This test's hub as hub.sh installs one (hub.installed_hub): its team.json is main()'s default --team, so
        the checkout is the code's own folder, and its records are main()'s default --db."""
        with patch.object(hub, "TEAM_DEFAULT", str(self.kit / "team.json")), \
                patch.object(hub, "DB_DEFAULT", self.path), patch.dict(hub.CFG, {"db_path": self.path}):
            yield

    def test_automatic_is_on_until_the_owner_turns_it_off(self):
        """Every fleet takes the newest release by itself (the owner, 22 October 2026: "it must be like that!"), and
        a fleet whose owner turned the switch off does not poll, with an entitlement or without one."""
        self.assertTrue(self.releases_state()["automatic"])
        code, answer = self.press("auto", automatic=False)
        self.assertEqual((code, answer["automatic"]), (200, False))
        self.assertFalse(self.releases_state()["automatic"])
        with self.installed():                                                     # a hub that could take a release
            self.assertEqual(self.swept(), [])                                     # with no entitlement
            self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
            self.assertEqual(self.swept(), [])                                     # and with one
        self.assertEqual(self.press("auto", automatic="yes")[0], 400)
        self.assertEqual(self.press("auto", automatic=True)[1]["automatic"], True)
        self.assertTrue(self.releases_state()["automatic"])

    def test_a_fleet_with_no_entitlement_polls_when_its_hub_runs_as_installed(self):
        """Founderizer is free (the owner, 10 November 2026), and the channel answers every fleet (the website's
        docs/CONTRACTS.md, "A call with no token"), so a fleet with no entitlement takes each release by itself too.
        Until the release that brought this, it did not ask at all. It asks with no token, at most once in the poll
        time. Its hub runs as hub.sh installs it, and its checkout is on the configuration ref."""
        self.assertFalse(self.releases_state()["entitlement"]["have_token"])
        latest = ("https://channel.invalid/releases/latest", None)
        with self.installed():
            self.assertTrue(hub.installed_hub())
            self.assertEqual(self.swept(), [latest])
            self.assertEqual(self.swept(), [])                                      # the poll's own gate holds
            self.assertEqual(self.swept(hub.now() + hub.RELEASE_POLL + 1), [latest])
        state = self.releases_state()
        self.assertEqual((state["last_check"]["status"], state["last_check"]["says"]), (200, None))
        self.assertEqual([one["revision"] for one in state["releases"]], ["a" * 40])  # what it found is kept
        self.assertFalse(state["entitlement"]["have_token"])

    def test_the_hub_that_hub_sh_installs_is_the_one_that_takes_releases_by_itself(self):
        """The check reads what main() reads with no argument, which is how the service of an installed hub starts it
        (`fleet.py service hub`). If a default of main() changed and the check did not, each fleet with no entitlement
        would stop taking releases, and no test with a patched default would show it."""
        source = inspect.getsource(hub.main)
        self.assertIn('ap.add_argument("--db", default=DB_DEFAULT', source)
        self.assertIn('ap.add_argument("--team", default=TEAM_DEFAULT)', source)
        self.assertIn('CFG["team_path"] = os.path.abspath(args.team)', source)
        self.assertIn("db_path = os.path.expanduser(args.db)", source)
        self.assertIn('CFG["db_path"] = db_path', source)
        self.assertEqual(hub.TEAM_DEFAULT, os.path.join(os.path.dirname(os.path.abspath(hub.__file__)), "team.json"))
        with patch.dict(hub.CFG, {"team_path": os.path.abspath(hub.TEAM_DEFAULT),
                                  "db_path": os.path.expanduser(hub.DB_DEFAULT)}):
            self.assertTrue(hub.installed_hub())                # only compares paths: nothing is read or written
        fleet_py = (Path(hub.__file__).parent / "fleet.py").read_text()
        self.assertIn('argv = [sys.executable, os.path.join(KIT, "hub.py")]\n', fleet_py)     # the unit: no argument

    def test_a_test_or_scratch_hub_with_no_entitlement_asks_nothing_and_writes_nothing(self):
        """A hub whose team.json is in a folder of its own (this test's), whose records are not at the default place,
        or an imported hub with no team_path, so that kit_dir gives the folder of the code: no release could move its
        code, so it never reaches the network by itself. Until the release that brought this, the missing
        entitlement kept each such hub off the network, the hubs of selftest.py among them; now this does."""
        self.assertFalse(hub.installed_hub())
        self.assertEqual(self.swept(), [])
        with self.installed(), patch.dict(hub.CFG, {"db_path": self.path + "-of-its-own"}):
            self.assertFalse(hub.installed_hub())               # its own checkout, and records of its own
            self.assertEqual(self.swept(), [])
        hub.CFG.pop("team_path")
        self.assertFalse(hub.installed_hub())
        self.assertEqual(self.swept(), [])
        self.assertIsNone(hub.kv_get("releases_swept"))         # and it wrote nothing, so a tick of it stays quiet

    def test_a_scratch_hub_with_no_entitlement_drops_a_wait_and_starts_nothing(self):
        """A wait that came with the records (a copy of a fleet that held one) is dropped at the first sweep, as
        before this release, and it starts no run, so no new session is held for it either (plan P0)."""
        hub.kv_set("release_waits", json.dumps({"revision": "a" * 40, "since": hub.now()}))
        self.assertTrue(hub.release_holds_starts())
        self.assertEqual(self.swept(), [])
        self.assertIsNone(hub.release_waiting())
        self.assertFalse(hub.release_holds_starts())

    def test_a_fleet_with_no_entitlement_on_another_branch_does_not_poll(self):
        """A checkout that is not on the configuration ref takes no release (releases.Update, step branch), so its
        hub does not ask by itself. It looks at its branch again one poll time later, not at each tick, and asks
        once the checkout is back on the configuration ref."""
        git("checkout", "-q", "-b", "main", cwd=self.kit)
        with self.installed():
            self.assertTrue(hub.installed_hub())
            self.assertEqual(self.swept(), [])
            self.assertTrue(hub.kv_get("releases_swept"))
            with patch.object(hub, "config_branch", lambda: self.fail("the branch was read again in the poll time")):
                self.assertEqual(self.swept(), [])
            git("checkout", "-q", hub.CONFIG_BRANCH, cwd=self.kit)
            self.assertEqual(self.swept(), [])                                      # still in the same poll time
            self.assertEqual(self.swept(hub.now() + hub.RELEASE_POLL + 1),
                             [("https://channel.invalid/releases/latest", None)])

    def test_a_fleet_that_holds_an_entitlement_polls_as_before_whatever_its_checkout(self):
        """The path from before this release, unchanged: a fleet with an entitlement asks with it as the bearer,
        and the folder of its code and the branch of its checkout change nothing. Here its hub does not run as
        installed, and the checkout is not on the configuration ref, which would each keep a fleet with no
        entitlement from asking."""
        token = self.token()
        self.assertEqual(self.press("entitlement", token=token)[0], 200)
        git("checkout", "-q", "-b", "main", cwd=self.kit)
        self.assertFalse(hub.installed_hub())
        self.assertEqual(self.swept(), [("https://channel.invalid/releases/latest", token)])
        self.assertEqual(self.swept(), [])                                          # the poll's own gate, as before
        self.assertEqual(self.swept(hub.now() + hub.RELEASE_POLL + 1),
                         [("https://channel.invalid/releases/latest", token)])

    def test_the_owners_own_check_does_not_postpone_the_automatic_update(self):
        """The sweep is the only thing that ever applies a release by itself, and it reaches the update only past
        its gate. While that gate read `releases_checked`, which **every** poll writes, the owner's own Check now
        held the automatic update back by up to RELEASE_POLL, and anything that checked more often than that held
        it back for ever -- and pressing Check now while waiting for a release is the one thing an owner does most.
        On this fleet 2026.11.27 is still `verified` and unapplied, with later releases gone past it, and 2026.11.32
        had to be forced through by hand -- both on 23 October 2026, with the fleet idle and automatic updates on.
        So the gate has a key of its own, `releases_swept`, and `releases_checked` goes on meaning what
        `last_check.at` shows the owner: when the channel was last asked, by anybody."""
        self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
        calls = []

        def count(*_a, **_k):
            calls.append(1)
            return {"status": 0, "manifest": None, "entitlement": None, "says": "the stand-in channel"}
        with patch.object(releases, "latest", count):
            self.assertEqual(self.press("check")[0], 200)           # the owner's own Check now
            self.finish()
            self.assertEqual(len(calls), 1)
            self.assertTrue(self.releases_state()["last_check"]["at"])       # it is still what he is shown
            self.assertIsNone(hub.kv_get("releases_swept"))         # a check is not a sweep, so it postpones none
            hub.release_sweep(hub.now())
            self.finish()
            self.assertEqual(len(calls), 2, "the owner's own check held the automatic poll back")
            self.assertTrue(hub.kv_get("releases_swept"))
            hub.release_sweep(hub.now())                             # and the sweep's own gate still holds
            self.finish()
            self.assertEqual(len(calls), 2)

    def test_an_automatic_fleet_polls_at_most_once_in_the_poll_time(self):
        self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
        with self.channel(manifest("a" * 40, hold=True)):
            hub.release_sweep(hub.now())
            self.finish()
            first = self.releases_state()["last_check"]["at"]
            self.assertTrue(first)
            hub.release_sweep(hub.now())
            self.finish()
            self.assertEqual(self.releases_state()["last_check"]["at"], first)
            hub.release_sweep(hub.now() + hub.RELEASE_POLL + 1)
            self.finish()
        self.assertGreater(self.releases_state()["last_check"]["at"], first)

    # ---- the entitlement

    def test_the_entitlement_is_kept_as_it_was_issued_and_shown_to_the_owner(self):
        code, answer = self.press("entitlement", token=self.token())
        self.assertEqual(code, 200, answer)
        self.assertEqual((answer["plan"], answer["machines"], answer["agents"], answer["verified"]),
                         ("monthly", 4, 6, True))
        shown = self.releases_state()["entitlement"]
        self.assertEqual((shown["plan"], shown["expired"], shown["have_token"]), ("monthly", False, True))
        self.assertEqual(hub.entitlement_token(), self.token())

    def test_an_expired_entitlement_changes_nothing_in_the_hub(self):
        """PRODUCT.md 4.2: nothing in the hub refuses work when it expires; only our side refuses. So it is kept,
        it is shown as expired, and every route of this hub answers exactly as before."""
        expired = self.token(until=1000000000)
        code, answer = self.press("entitlement", token=expired)
        self.assertEqual((code, answer["expired"]), (200, True))
        self.assertEqual(hub.entitlement_token(), expired)
        self.assertEqual(self.request()[0], 200)                            # /ui/state still answers
        self.assertEqual(self.releases_state()["entitlement"]["expired"], True)
        with self.channel(manifest("a" * 40)):                              # and a poll still carries it
            self.assertEqual(self.press("check")[0], 200)
            self.finish()
        self.assertEqual(self.releases_state()["releases"][0]["state"], "verified")
        hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('t','vps','manager','working',?)",
                (hub.now(),))
        self.assertEqual(self.request("/ui/state")[1]["tasks"][0]["state"], "working")
        self.assertEqual(hub.q1("SELECT count(*) n FROM log WHERE what LIKE '%refus%'")["n"], 0)

    def test_the_entitlement_token_is_written_nowhere_a_reader_could_find_it(self):
        secret = self.token()
        self.assertEqual(self.press("entitlement", token=secret)[0], 200)
        for table, column in (("ui_controls", "body"), ("ui_controls", "result"), ("log", "what")):
            for row in hub.q(f"SELECT {column} AS value FROM {table}"):
                self.assertNotIn(secret, row["value"] or "", f"{table}.{column}")
        self.assertNotIn(secret, json.dumps(self.releases_state()))
        self.assertIn(hashlib.sha256(secret.encode()).hexdigest(),
                      hub.q1("SELECT body FROM ui_controls")["body"])

    def test_an_entitlement_the_hub_cannot_read_or_that_is_for_another_fleet_is_refused(self):
        self.assertEqual(self.press("entitlement", token="not-a-token")[0], 400)
        self.assertEqual(self.press("entitlement", token=self.token(fleet="f" * 16))[0], 409)
        self.assertEqual(self.press("entitlement", token="")[0], 400)
        self.assertFalse(self.releases_state()["entitlement"]["have_token"])

    def test_the_hub_checks_the_entitlement_with_the_entitlement_key_and_not_the_release_key(self):
        """The one that was wrong until 18 October 2026: `store_entitlement` passed the release key, so every real
        entitlement — which the website signs with its entitlement key — would have landed as unverified. The
        token is still kept and shown either way, because only our side refuses (4.2); it is marked, not refused."""
        self.assertEqual(hub.entitlement_keys(), (PLAN_KEY,))
        self.assertEqual(hub.release_keys(), (KEY,))
        self.assertTrue(self.press("entitlement", token=self.token())[1]["verified"])
        signed_with_the_release_key = self.token(seed=SEED)
        code, answer = self.press("entitlement", token=signed_with_the_release_key)
        self.assertEqual((code, answer["verified"]), (200, False))
        self.assertEqual(hub.entitlement_token(), signed_with_the_release_key)
        said = hub.q1("SELECT what FROM log WHERE what LIKE 'entitlement kept%' ORDER BY id DESC")["what"]
        self.assertIn("not signed by our entitlement key", said)
        (self.kit / releases.ENTITLEMENT_KEY_FILE).unlink()      # a checkout with no entitlement key verifies none
        self.assertEqual(hub.entitlement_keys(), ())
        self.assertFalse(self.press("entitlement", token=self.token())[1]["verified"])

    def test_a_fleet_with_no_id_takes_the_one_its_entitlement_names(self):
        hub.kv_set("fleet_id", None)
        token = releases.sign_entitlement(PLAN_SEED, {"fleet": "1234567890abcdef", "plan": "yearly",
                                                      "until": 2000000000, "machines": 4, "agents": 6})
        self.assertEqual(self.press("entitlement", token=token)[1]["fleet"], "1234567890abcdef")
        self.assertEqual(hub.kv_get("fleet_id"), "1234567890abcdef")

    def test_a_fresh_entitlement_from_the_channel_replaces_the_old_one(self):
        self.press("entitlement", token=self.token())
        fresh = self.token(until=2100000000)
        with self.channel(dict(manifest("a" * 40), entitlement=fresh)):
            self.press("check")
            self.finish()
        self.assertEqual(hub.entitlement_token(), fresh)
        self.assertEqual(self.releases_state()["entitlement"]["until"], 2100000000)

    def test_what_the_channel_said_about_this_fleet_is_kept(self):
        self.press("entitlement", token=self.token())
        with self.channel({}, 403):
            self.press("check")
            self.finish()
        shown = self.releases_state()["entitlement"]
        self.assertEqual(shown["channel_said"], "the release channel refused this fleet (403)")
        self.assertTrue(shown["channel_at"])
        self.assertTrue(shown["have_token"])            # and the token is still there, because nothing enforces

    # ---- what the owner alone may do

    def test_every_release_route_refuses_another_address(self):
        for path, body in (("releases?db=test-generation", None), ("releases/check", self.command()),
                           ("releases/update", self.command()), ("releases/auto", self.command(automatic=True)),
                           ("releases/entitlement", self.command(token=self.token()))):
            code, data = self.request("/ui/" + path, body, source="127.0.0.9")
            self.assertEqual(code, 403, f"{path}: {data}")
        self.assertEqual(hub.q1("SELECT count(*) n FROM ui_controls")["n"], 0)


# ---------------------------------------------------------------- one click, end to end

class HubUpdates(Repositories, HubRoutes):
    """The owner's Update, through the route, on the repositories of `Repositories`."""

    def setUp(self):
        Repositories.setUp(self)
        OwnerAPI.setUp(self)
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG["team_path"] = str(self.kit / "team.json")
        hub.CFG["release_channel"] = "https://channel.invalid"
        hub.CFG["release_upstream"] = self.upstream
        hub.CFG["hub_restart"] = ["true"]
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        hub._release["thread"] = None
        git("remote", "set-url", "origin", self.origin, cwd=self.kit)

    def tearDown(self):
        HubRoutes.tearDown(self)
        hub._code_diffs.clear()

    def run_update(self, released, run=None, **how):
        """The owner's click, with the channel offering this release and the two checks answered from a table."""
        with self.channel(manifest(released, **how)), \
                patch.object(releases, "Update", functools.partial(releases.Update, run=run or self.runner())):
            code, answer = self.press("update")
            self.finish()
        return code, answer

    def newest(self):
        return self.releases_state()["releases"][0]

    def test_one_click_moves_this_fleet_to_the_released_revision(self):
        released = self.publish(self.code(2), "Developer changed the hub")
        code, answer = self.run_update(released)
        self.assertEqual((code, answer["started"], answer["applying"]), (200, True, True))
        one = self.newest()
        self.assertEqual((one["state"], one["step"], one["applied"]), (releases.DONE, "follow", True))
        self.assertEqual(one["pinned"], self.pinned)
        self.assertEqual(self.head(), one["reached"])
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), one["reached"])
        self.assertEqual(self.releases_state()["revision"], one["reached"])
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")

    def test_a_run_that_a_stop_of_the_hub_cut_off_ends_at_the_next_start(self):
        """The run lives in the hub's process, so a stop during it leaves its row at updating for ever. The next start
        ends that row as a failed run, and the next update of the release takes it as any other."""
        released = self.publish(self.code(2), "Developer changed the hub")
        hub.ins("INSERT INTO releases(seen,revision,version,notes,minimum,hold,state,started) VALUES(?,?,?,?,?,?,?,?)",
                (hub.now(), released, "2026.10.2", None, None, 0, "updating", hub.now()))
        hub.settle_releases()
        row = self.newest()
        self.assertEqual((row["state"], row["step"]), (releases.FAILED, "merge"))
        self.assertIn("hub stopped", row["says"])
        self.assertIsNotNone(row["finished_at"])
        code, _ = self.run_update(released)
        self.assertEqual((code, self.newest()["state"], self.head()), (200, releases.DONE, self.newest()["reached"]))
        self.assertIn("settle_releases(ask=not restored)", inspect.getsource(hub.main))    # the hub's start runs it

    def test_a_write_of_the_hub_s_own_that_a_cut_left_on_the_ref_is_taken_back_before_the_run(self):
        """The cut came before the run, and the fleet was idle, so no write took the commit back (hub.KIT_PUSHED). A
        run merges onto the ref's tip, and would carry that write in without the steps it never ran: it takes the
        commit back first (settle_kit_push), and the release goes onto the commit that undoes it."""
        cut = self.cut_write()
        hub.kv_set(hub.KIT_PUSHED, cut)
        code, _ = self.run_update(self.publish(self.code(2)))
        one = self.newest()
        self.assertEqual((code, one["state"], one["step"]), (200, releases.DONE, "follow"), one["says"])
        self.assertEqual((self.head(), self.ref(hub.CONFIG_BRANCH)), (one["reached"], one["reached"]))
        self.assertIn(cut, git("rev-list", one["reached"], cwd=self.kit).split("\n"))
        self.assertNotIn("title", json.loads((self.kit / "team.json").read_text())["agents"]["vps"])
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")
        self.assertIsNone(hub.kv_get(hub.KIT_PUSHED))

    def test_a_write_of_the_hub_s_own_cut_off_during_the_run_waits_for_the_next_run(self):
        """The cut came while the run checked the release: the run does not merge onto it, and ends rolled back at
        the push. The next run takes the commit back first and takes the release."""
        def cut(_):
            commit = self.cut_write()
            hub.kv_set(hub.KIT_PUSHED, commit)
            return commit
        released = self.publish(self.code(2))
        code, _ = self.run_update(released, run=self.runner_that(cut))
        one = self.newest()
        self.assertEqual((code, one["state"], one["step"]), (200, releases.ROLLED_BACK, "push"), one["says"])
        self.assertEqual((self.ref(hub.CONFIG_BRANCH), self.head()), (self.wrote[0], self.pinned))
        code, _ = self.run_update(released)
        one = self.newest()
        self.assertEqual((code, one["state"], self.head()), (200, releases.DONE, one["reached"]), one["says"])
        self.assertIn(self.wrote[0], git("rev-list", one["reached"], cwd=self.kit).split("\n"))
        self.assertNotIn("title", json.loads((self.kit / "team.json").read_text())["agents"]["vps"])

    def test_a_release_this_fleet_took_asks_every_machine_for_its_idle_update(self):
        """The hub's own machine too. Its agent's helper has its own home, its own checkout and its own user
        service, so it takes a release exactly as a worker does; leaving it out is what kept the owner's hub two
        releases behind while `/ui/health` warned about it (hub.request_update)."""
        code, _ = self.run_update(self.publish(self.code(2)))
        self.assertEqual(code, 200)
        reached = self.newest()["reached"]
        for agent in ("vps", "manager"):
            update = hub.q1("SELECT * FROM machine_updates WHERE agent=?", (agent,))
            self.assertEqual((update["state"], update["desired"]), ("requested", reached), agent)
            event = hub.q1("SELECT * FROM events WHERE agent=? AND kind='update' ORDER BY id DESC", (agent,))
            self.assertEqual(json.loads(event["extra"])["desired_revision"], reached, agent)
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC")["text"]
        self.assertIn("took release", said)
        self.assertIn(reached[:12], said)

    def test_a_release_on_the_ref_that_this_hub_did_not_follow_still_asks_every_machine(self):
        """FAILED at follow: the push landed and only the hub's own checkout stayed. Every machine takes the release
        at its next sync all the same, so each is asked for its idle update, and its helper restarts onto what its
        checkout then runs instead of at some later restart. The hub itself does not restart: it did not move."""
        inner = self.runner()

        def run(argv, timeout=None, cwd=None, input=None):
            if argv[:6] == ["git", "-C", str(self.kit), "fetch", "-q", "origin"]:
                return 1, "", "fatal: the configuration ref's repository did not answer"
            return inner(argv, timeout=timeout, cwd=cwd, input=input)
        restarts = []
        with patch.object(hub, "restart_hub_soon", lambda *args, **kw: restarts.append(args)):
            code, _ = self.run_update(self.publish(self.code(2)), run=run)
        one = self.newest()
        self.assertEqual((code, one["state"], one["step"]), (200, releases.FAILED, "follow"), one["says"])
        self.assertIn("then restart the hub's service", one["says"])
        self.assertEqual((self.ref(hub.CONFIG_BRANCH), self.head()), (one["reached"], self.pinned))
        self.assertEqual([tuple(r) for r in hub.q("SELECT agent, state, desired FROM machine_updates ORDER BY agent")],
                         [("manager", "requested", one["reached"]), ("vps", "requested", one["reached"])])
        self.assertEqual(restarts, [])
        self.assertIsNone(hub.q1("SELECT 1 FROM events WHERE agent='manager' AND kind='say' AND text LIKE ?",
                                 ("%took release%",)))

    def test_a_run_cut_off_after_its_push_still_asks_every_machine(self):
        """The push landed, this hub's own checkout followed it, and the run was cut off before finish_release: by an
        error in the hub's thread (release_work), or by a stop of the hub, whose row settle_releases ends at the next
        start. Every machine takes the release at its next sync all the same, and the next run of it stops at KEPT
        "already" and asks nobody. So the row keeps `reached` from the moment the push lands, and the end of a run
        that was cut off asks every machine for its idle update, as finish_release does. After an error the hub's
        process still runs the code it started with, so it restarts; after a stop it already runs its checkout."""
        def cut_by_an_error(released):
            inner = self.runner()

            def run(argv, timeout=None, cwd=None, input=None):      # the hub's own fast-forward, then an error
                answer = inner(argv, timeout=timeout, cwd=cwd, input=input)
                if argv[:6] == ["git", "-C", str(self.kit), "merge", "-q", "--ff-only"]:
                    raise RuntimeError("the hub broke after its checkout followed the ref")
                return answer
            with patch.object(hub.traceback, "print_exc", lambda: None):
                return self.run_update(released, run=run)[0]

        def cut_by_a_stop(released):
            # The owner's own commit while the checks run: the first push is refused and the release is merged again
            # onto the ref's new tip, so the revision that landed is not the one that was merged first.
            run = self.runner_that(lambda n: self.owner_commit("profiles/vps.md", PROFILE + "\n**Very careful.**\n"))
            with patch.object(hub, "finish_release", lambda *args, **kw: None):     # the process ends here
                code = self.run_update(released, run=run)[0]
            hub.settle_releases()                                                    # and starts again
            return code

        restarts = []
        with patch.object(hub, "restart_hub_soon", lambda *args, **kw: restarts.append(args)):
            for number, cut, restart in ((2, cut_by_an_error, True), (3, cut_by_a_stop, False)):
                hub.q("DELETE FROM machine_updates")
                restarts.clear()
                pinned, released = self.head(), self.publish(self.code(number))
                code = cut(released)
                one = self.newest()
                self.assertEqual((code, one["state"], one["step"]), (200, releases.FAILED, "merge"), cut.__name__)
                self.assertEqual((self.ref(hub.CONFIG_BRANCH), self.head()), (one["reached"], one["reached"]),
                                 cut.__name__)
                self.assertEqual([tuple(r) for r in hub.q("SELECT agent, state, desired FROM machine_updates "
                                                          "ORDER BY agent")],
                                 [("manager", "requested", one["reached"]), ("vps", "requested", one["reached"])],
                                 cut.__name__)
                hub.q("DELETE FROM machine_updates")
                hub.settle_releases()                   # a later start: this run is settled, and asks nobody again
                self.run_update(released)               # nor does the next run of the release
                self.assertEqual((self.newest()["state"], self.newest()["step"]), (releases.KEPT, "already"))
                self.assertEqual(hub.q("SELECT * FROM machine_updates"), [], cut.__name__)
                self.assertEqual(restarts, [(pinned, one["reached"])] if restart else [], cut.__name__)

    def test_an_ask_that_fails_is_made_again_and_never_keeps_a_run_from_ending(self):
        """The machines are asked before a run's row ends, so an ask that raises in finish_release leaves the row at
        updating, and the error handler's settle_releases asks again. An ask that raises there is skipped: at the
        hub's start, before it serves anything, a row left at updating would meet the same failure at every later
        start. A start on restored records ends such a row and asks nobody."""
        real, calls = hub.request_update, []

        def ask(agent, desired):            # the second and the third ask fail: one in each of the two places
            calls.append(agent)
            if len(calls) in (2, 3):
                raise RuntimeError("database disk image is malformed")
            return real(agent, desired)
        with patch.object(hub, "request_update", ask), patch.object(hub, "restart_hub_soon", lambda *a, **kw: None), \
                patch.object(hub.traceback, "print_exc", lambda: None):
            code, _ = self.run_update(self.publish(self.code(2)))
        one = self.newest()
        self.assertEqual((code, one["state"], one["step"], len(calls)), (200, releases.FAILED, "merge", 4))
        self.assertEqual([tuple(r) for r in hub.q("SELECT agent, state, desired FROM machine_updates ORDER BY agent")],
                         [("manager", "requested", one["reached"]), ("vps", "requested", one["reached"])])
        hub.q("DELETE FROM machine_updates")
        hub.q("UPDATE releases SET state='updating' WHERE id=?", (one["id"],))      # restored records of such a run
        hub.settle_releases(ask=False)
        self.assertEqual((self.newest()["state"], hub.q("SELECT * FROM machine_updates")), (releases.FAILED, []))

    def test_a_deliberately_broken_release_returns_this_fleet_to_the_pinned_revision_by_itself(self):
        released = self.publish(self.code(2), "a release that breaks the fleet")
        broken = "110 of 121 checks passed. FAILED: ['the hub answers nothing', 'a task cannot be created']"
        code, _ = self.run_update(released, run=self.runner(selftest=(1, broken, "")))
        self.assertEqual(code, 200)
        one = self.newest()
        self.assertEqual((one["state"], one["step"]), (releases.ROLLED_BACK, "selftest"))
        self.assertEqual(one["pinned"], self.pinned)
        self.assertIsNone(one["reached"])
        self.assertIn("the hub answers nothing", one["says"])
        self.assertEqual(self.head(), self.pinned)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), self.pinned)
        self.assertEqual(self.releases_state()["revision"], self.pinned)
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 1\n")
        self.assertIsNone(hub.q1("SELECT * FROM machine_updates WHERE agent='vps'"))

    def test_a_held_release_is_refused_with_automatic_updates_on(self):
        hub.set_releases_automatic(True)
        released = self.publish(self.code(2))
        code, _ = self.run_update(released, hold=True)
        self.assertEqual(code, 200)
        one = self.newest()
        self.assertEqual((one["state"], one["step"], one["hold"]), (releases.KEPT, "hold", True))
        self.assertEqual(self.head(), self.pinned)
        self.assertEqual(self.ref(hub.CONFIG_BRANCH), self.pinned)
        self.assertIsNone(hub.q1("SELECT * FROM machine_updates WHERE agent='vps'"))

    def sweep(self, fetch):
        """One automatic sweep after the poll time, run to its end, and each release's (state, step) by version."""
        hub.kv_set("releases_swept", None)
        with patch.object(releases, "latest", functools.partial(releases.latest, fetch=fetch)), \
                patch.object(releases, "Update", functools.partial(releases.Update, run=self.runner())):
            hub.release_sweep(hub.now())
            self.finish()
        return {r["version"]: (r["state"], r["step"]) for r in self.releases_state()["releases"]}

    def marked(self):
        """The release before (2026.11.121) and the marked release (2026.11.122) that needs it, both published, and
        the channel's table with only the marked one in it."""
        self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
        before = self.publish(self.code(2), "the change the release before must accept")
        marked = self.publish(self.code(3), "the change that needs it")
        return before, {"latest": manifest(marked, "2026.11.122", minimum=before)}

    def test_a_fleet_takes_the_release_a_marked_one_needs_before_it(self):
        """COORDINATION.md "Readiness": a commit marked `Release-minimum: previous` needs the release before it, which
        the website signs as the minimum of every release from that one on. The sweep takes only the newest release,
        so a fleet that had not applied the release before takes it from the channel by its revision, and the marked
        one at the next sweep. It never skips the release before."""
        before, table = self.marked()
        table[before] = manifest(before, "2026.11.121")
        fetch = channel_of(table)
        self.assertEqual(self.sweep(fetch), {"2026.11.122": ("verified", None), "2026.11.121": (releases.DONE, "follow")})
        self.assertEqual(fetch.seen, ["https://channel.invalid/releases/latest",
                                      "https://channel.invalid/releases/" + before])
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")
        self.assertEqual(self.sweep(fetch)["2026.11.122"], (releases.DONE, "follow"))
        self.assertEqual(fetch.seen[2:], ["https://channel.invalid/releases/latest"])
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 3\n")
        self.assertEqual([r["version"] for r in self.releases_state()["releases"]], ["2026.11.122", "2026.11.121"])

    def test_a_marked_release_waits_at_its_minimum_until_this_fleet_has_the_release_before(self):
        """A channel that cannot give the release before (a site older than the mark): the marked one is kept at the
        step minimum and nothing moves. Once the channel gives it, this fleet takes it, then the marked one."""
        before, table = self.marked()
        fetch = channel_of(table)
        self.assertEqual(self.sweep(fetch), {"2026.11.122": (releases.KEPT, "minimum")})
        self.assertEqual((self.head(), self.ref(hub.CONFIG_BRANCH)), (self.pinned, self.pinned))
        self.assertIn(f"needs the release at {before[:12]} first, and the release channel did not give it",
                      hub.q1("SELECT what FROM log WHERE what LIKE '%did not give it%'")["what"])
        table[before] = manifest(before, "2026.11.121")
        self.assertEqual(self.sweep(fetch), {"2026.11.122": (releases.KEPT, "minimum"),
                                             "2026.11.121": (releases.DONE, "follow")})
        self.assertEqual(self.sweep(fetch)["2026.11.122"], (releases.DONE, "follow"))
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 3\n")

    def test_a_release_this_fleet_meets_asks_the_channel_nothing_more(self):
        """An unmarked release behaves as before the mark: one read of the channel, and the release is taken. So
        does a release whose minimum this fleet already has."""
        self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
        released = self.publish(self.code(2))
        for minimum in (None, self.seeded):
            fetch = channel_of({"latest": manifest(released, minimum=minimum)})
            with patch.object(releases, "latest", functools.partial(releases.latest, fetch=fetch)):
                self.assertEqual(self.press("check")[0], 200)
                self.finish()
            self.assertEqual(fetch.seen, ["https://channel.invalid/releases/latest"], minimum)
        fetch = channel_of({"latest": manifest(released)})
        self.assertEqual(self.sweep(fetch), {"2026.10.2": (releases.DONE, "follow")})
        self.assertEqual(fetch.seen, ["https://channel.invalid/releases/latest"])

    def test_a_fleet_with_no_entitlement_takes_a_release_by_itself(self):
        """The whole of it on real repositories (the owner, 10 November 2026: Founderizer is free, with no account):
        a fleet that never held an entitlement, whose hub runs as installed on the configuration ref, finds the
        release at its sweep, asks with no token, and moves onto it as a fleet with one does."""
        released = self.publish(self.code(2), "Developer changed the hub")
        fetch = answers(manifest(released))
        with self.installed():
            self.assertEqual(self.sweep(fetch), {"2026.10.2": (releases.DONE, "follow")})
        self.assertEqual([(one["url"], one["token"]) for one in fetch.seen],
                         [("https://channel.invalid/releases/latest", None)])
        one = self.newest()
        self.assertEqual((one["automatic"], one["pinned"]), (True, self.pinned))
        self.assertEqual((self.head(), self.ref(hub.CONFIG_BRANCH)), (one["reached"], one["reached"]))
        self.assertEqual((self.kit / "hub.py").read_text(), "# the hub\nVERSION = 2\n")
        self.assertFalse(self.releases_state()["entitlement"]["have_token"])

    def test_a_working_fleet_is_not_updated(self):
        hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('t','vps','manager','working',?)",
                (hub.now(),))
        hub.touch("vps")        # plan P0: its helper is online and lists no window, so its turn may run
        released = self.publish(self.code(2))
        with self.channel(manifest(released)):
            code, answer = self.press("update")
        self.assertEqual(code, 409, answer)
        self.assertIn("waits until no turn runs: T-1", answer["error"])
        self.assertEqual(hub.q1("SELECT count(*) n FROM releases")["n"], 0)
        self.assertEqual(self.head(), self.pinned)

    def test_a_task_that_is_created_during_a_run_is_not_cut_by_the_update(self):
        """The one cost P6 left: the fleet is read as idle when the run begins, both checks take minutes, and the
        hub restarts its own service at the end, which drops whatever session is live at that moment. So no task
        session starts while an update run is going. The task is neither refused nor lost: it waits, nobody is told
        that its machine may be offline, and its helper is given the start when the run has ended."""
        released = self.publish(self.code(2))
        checking, go = threading.Event(), threading.Event()
        table = self.runner()

        def run(argv, timeout=None, cwd=None, input=None):
            if argv[-1].endswith("selftest.py"):
                checking.set()              # the run is in its checks: minutes from the push and from the restart
                go.wait(30)
            return table(argv, timeout=timeout, cwd=cwd, input=input)

        with self.channel(manifest(released)), \
                patch.object(releases, "Update", functools.partial(releases.Update, run=run)):
            self.assertEqual(self.press("update")[0], 200)
            self.assertTrue(checking.wait(60), "the run never reached its checks")
            tid = self.task_for()
            self.assertTrue(hub.release_applying())
            self.assertEqual(self.starts(), [], "a session started during the run, and the restart would drop it")
            with patch.dict(hub.CFG, {"silence": 0, "question_wait": 120, "manager_silence": 120,
                                      "stop_after": 60, "offline_after": 90, "tick": 5}):
                hub.tick()
            self.assertEqual(hub.q1("SELECT nudge_level FROM tasks WHERE id=?", (tid,))["nudge_level"], 0)
            go.set()
            self.finish()
        self.assertEqual(self.newest()["state"], releases.DONE)         # the run published and asked for the restart
        self.assertFalse(hub.release_applying())
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (tid,))["state"], "submitted")
        self.assertEqual(self.starts(), [hub.tref(tid)])               # and now that task may start

    def test_the_schema_check_gets_a_copy_of_the_records_and_nothing_of_it_is_left(self):
        """The hub hands the released code a copy of its own database (`test_schema_guard.py` runs that check for
        real). It is the one copy this hub writes on its own machine, so the run must take it away again."""
        seen = {}
        made = releases.Update

        def watch(*args, **how):
            seen["database"] = how.get("database")
            seen["bytes"] = os.path.getsize(how["database"]) if how.get("database") else None
            return made(*args, **how)
        with patch.object(releases, "Update", watch):
            code, _ = self.run_update(self.publish(self.code(2)))
        self.assertEqual(code, 200)
        self.assertEqual(self.newest()["state"], releases.DONE)
        self.assertTrue(seen["bytes"], "the schema check was given no records to read")
        self.assertIn("founderizer-records-", seen["database"])
        self.assertFalse(os.path.exists(seen["database"]), "the copy of the records outlived the run")
        self.assertFalse(os.path.exists(os.path.dirname(seen["database"])))

    def test_the_hub_restarts_itself_only_when_the_release_changed_a_fleet_file(self):
        """The hub serves the revision it started with, so new code reaches it only with a restart of its own
        service (COORDINATION.md rule 6) — and a customer has no console. A release that changed no Fleet file
        restarts nothing, and a fleet that set no restart command restarts nothing either."""
        code, _ = self.run_update(self.publish(self.code(2)))
        self.assertEqual(code, 200)
        reached = self.newest()["reached"]
        self.assertEqual(hub.restart_hub_soon(self.pinned, reached), ["true"])
        self.assertIsNone(hub.restart_hub_soon(reached, reached))
        self.pinned = reached

        def document(work):
            (work / "README.md").write_text("# Founderizer\n\nA document, not code.\n")
        self.assertEqual(self.run_update(self.publish(document, "a document"))[0], 200)
        one = self.newest()
        self.assertEqual(one["state"], releases.DONE)
        self.assertIsNone(hub.restart_hub_soon(one["pinned"], one["reached"]))
        hub.CFG["hub_restart"] = []
        self.assertIsNone(hub.restart_hub_soon(self.pinned, "0" * 40))
        time.sleep(hub.RESTART_DELAY + 0.5)         # the restart threads of this test end before the database does

    def test_the_hub_restart_takes_an_old_bridge_to_the_new_code_until_the_bridge_sends_its_code(self):
        """A bridge from before its own code check runs the code it started with until its server restarts, so the
        hub's restart for a release restarts it first. Once a bridge sends its code, it restarts by itself, and the
        hub's restart leaves it alone. A fleet with its own restart command (here every test's "true") gets neither."""
        ran, real = [], subprocess.run

        def run(argv, *args, **how):
            if argv in (hub.BRIDGE_RESTART, hub.HUB_RESTART):
                ran.append(argv)
                return subprocess.CompletedProcess(argv, 0, "", "")
            return real(argv, *args, **how)

        def restart():
            ran.clear()
            hub.restart_hub_soon(None, None, always=True)
            for thread in threading.enumerate():
                if thread.name == "release-restart":
                    thread.join(5)
            return list(ran)
        with patch.object(hub, "RESTART_DELAY", 0), patch.object(hub.subprocess, "run", run):
            self.assertEqual(restart(), [])
            hub.CFG.pop("hub_restart")
            self.assertEqual(restart(), [hub.BRIDGE_RESTART, hub.HUB_RESTART])
            hub.kv_set("bridge_code", "c0de" * 16)
            self.assertEqual(restart(), [hub.HUB_RESTART])

    def test_a_fleet_whose_file_carries_both_keys_takes_a_release_signed_with_the_new_one(self):
        """The hub hands the whole set to the check, so the second step of a rotation works end to end: this fleet
        took the release that added the next key, and the release after it is signed with that key alone."""
        (self.kit / releases.KEY_FILE).write_text(base64.b64encode(KEY).decode() + "\n"
                                                  + base64.b64encode(NEXT_KEY).decode() + "\n")
        git("commit", "-q", "-a", "-m", "the release that brought the next key", cwd=self.kit)
        git("push", "-q", "origin", "HEAD:" + hub.CONFIG_BRANCH, cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        self.pinned = self.head()
        self.assertTrue(self.releases_state()["have_release_key"])
        code, _ = self.run_update(self.publish(self.code(2)), seed=NEXT_SEED)
        self.assertEqual(code, 200)
        one = self.newest()
        self.assertEqual((one["state"], one["applied"]), (releases.DONE, True))
        self.assertEqual(self.head(), one["reached"])

    def test_a_fleet_with_no_release_key_takes_no_release(self):
        (self.kit / releases.KEY_FILE).unlink()
        git("commit", "-q", "-a", "-m", "the key file is gone", cwd=self.kit)
        git("push", "-q", "origin", "HEAD:" + hub.CONFIG_BRANCH, cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        self.pinned = self.head()
        self.assertFalse(self.releases_state()["have_release_key"])
        code, _ = self.run_update(self.publish(self.code(2)))
        self.assertEqual(code, 200)
        state = self.releases_state()
        self.assertEqual(state["releases"], [])
        self.assertIn("no release key", state["last_check"]["says"])
        self.assertEqual(self.head(), self.pinned)


if __name__ == "__main__":
    unittest.main()

"""Pings to the owner's phone (MOBILE-APP.md 9, owner feature push): the phone's push token and its seal key, one
ping for each new Needs-you item, what our side carries, and the states of a ping. A local hub with a test source
address for the Mac and the phone, and a stand-in for our side's push route (the release channel's /api/push) on loopback.
No real device, key, network or AI call."""
import base64
import hashlib
import json
import os
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import hub
import leftovers
import push
from test_mobile import MAC, OTHER, PHONE, Devices

TOKEN = "ab" * 32                                   # a device token as Apple gives it: 32 bytes in hexadecimal
KEY = bytes(range(32))                              # the phone's own seal key
SEAL = base64.b64encode(KEY).decode()
ENTITLEMENT = "eyJmbGVldCI6IjBmMWUyZDNjNGI1YTY5NzgifQ.c2lnbmVk"
# B9 10.7: a member's phone gives its push token sealed, v1.<key id>.<448 of b64u>. The hub never opens it, so a
# value of that form is all that the route needs here; the phone's own values are in
# app/vectors/member-token-vectors.json
SEALED = "v1.test0key." + base64.urlsafe_b64encode(bytes(range(256)) + bytes(80)).decode()


def member_tokens():
    """The phone's values of app/vectors/member-token-vectors.json, or None in a published clone, which has no app
    folder (the file is found through leftovers.ROOT, never through this file's own place)."""
    path = os.path.join(leftovers.ROOT, "app", "vectors", "member-token-vectors.json")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="ascii") as f:
        return json.load(f)


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from test_mobile, whose own tests stay in their own file."""
    suite = unittest.TestSuite()
    for cls in (Seal, Token, Queue, Sender, Present, Badge, MemberRoute):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class OurSide(BaseHTTPRequestHandler):
    """Our side's push route, as far as the hub can tell: it keeps what it was sent and answers server.answer, which
    is Apple's answer in a 200, or a refusal of its own, and the headers of a third element if there is one."""
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.got.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                "body": json.loads(body), "raw": body.decode()})
        if getattr(self.server, "during", None):        # what happens at our side while the call runs
            self.server.during()
        status, answer, *more = self.server.answer
        out = json.dumps(answer).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        for name, value in (more[0] if more else {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *_args):
        pass


class Quiet(BaseHTTPRequestHandler):
    """Our side, when it takes the ping and never answers."""
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.stop.wait(10)

    def log_message(self, *_args):
        pass


class PushCase(Devices):
    def setUp(self):
        super().setUp()
        self.side = ThreadingHTTPServer(("127.0.0.1", 0), OurSide)
        self.side.got, self.side.answer = [], (200, {"status": 200, "reason": ""})
        # a short poll: tearDown's shutdown() waits for the loop's next look, which was up to 0.5 s in each test
        threading.Thread(target=self.side.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        hub.CFG["release_channel"] = f"http://127.0.0.1:{self.side.server_port}"
        hub.q("INSERT INTO entitlement(id,fleet,token,plan,until,machines,agents,verified,stored) "
              "VALUES(1,'0f1e2d3c4b5a6978',?,'founder-monthly',?,5,10,1,?)", (ENTITLEMENT, hub.now() + 86400, hub.now()))
        hub._ping_hold.update(until=0.0, licence=None)      # a hold is in memory: none comes from another test
        hub.PING_HELD_LINE.clear()
        hub.PHONE_HOLDS.clear()
        hub.BADGE.update(off=False, until=0.0)
        hub.BADGE_TRIED.clear()

    def tearDown(self):
        self.side.shutdown()
        self.side.server_close()
        hub.CFG.pop("release_channel", None)
        hub._ping_hold["until"] = 0.0
        hub.BADGE.update(off=False, until=0.0)
        hub.BADGE_TRIED.clear()
        super().tearDown()

    def give(self, key, device="iphone", source=PHONE, **body):
        return self.call(f"/ui/owner/devices/{device}/push",
                         dict({"request_id": str(uuid.uuid4()), "db": "test-generation", "token": TOKEN,
                               "environment": "production"}, **body), source=source, token=key)

    def raise_item(self, title="Pay for the domain?", **extra):
        return int(hub.t_raise_needs_you("manager", dict({"title": title, "why": "The card is the owner's",
                                                          "what_to_do": "Press one", "reason": "person"}, **extra))
                   .split("N-", 1)[1].split(".", 1)[0])

    def pings(self):
        return [dict(r) for r in hub.q("SELECT * FROM pings ORDER BY id")]


class Seal(unittest.TestCase):
    """ChaCha20-Poly1305 as the phone's CryptoKit seals and opens it: the same bytes, both ways."""
    # Made by CryptoKit on this Mac (ChaChaPoly.seal, key 0x80...0x9f, this nonce), 3 November 2026, and made again
    # on 11 November 2026 for this text with an example database id.
    NONCE = bytes([7, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47])
    TEXT = (b'{"body":"May I restart the database tonight at 23:00?","db":"0a1b2c3d4e5f","need":23,'
            b'"options":["Yes, restart","Not tonight"],"title":"Atlas"}')
    CRYPTOKIT = ("070000004041424344454647e4598b326584628037afee8216c82adca4b3fc5e7b754eaab5eff0e334f662c72fedae18d8e1"
                 "3042dfb2c62f9baf72da463e825e814b416d04c6a7f533887a689e83a76c262d8b998a48f2e120030c1cace173f7b0816e91"
                 "5389c3c5486683947edfdee6cc4b7f97e36ed7379089ca005b577823ba5a02bec11e17d980c3dd101c8013335ba4ef822b00"
                 "472c733e6d8a0fdf765a6acb6754d0f98ab88f75")

    def test_the_hub_seals_what_cryptokit_seals(self):
        key = bytes(range(0x80, 0xa0))
        self.assertEqual(push.seal(key, self.TEXT, self.NONCE).hex(), self.CRYPTOKIT)
        self.assertEqual(push.open_sealed(key, bytes.fromhex(self.CRYPTOKIT)), self.TEXT)

    def test_a_changed_byte_or_another_key_does_not_open(self):
        key = bytes(range(0x80, 0xa0))
        sealed = bytearray(bytes.fromhex(self.CRYPTOKIT))
        sealed[20] ^= 1
        with self.assertRaises(ValueError):
            push.open_sealed(key, bytes(sealed))
        with self.assertRaises(ValueError):
            push.open_sealed(KEY, bytes.fromhex(self.CRYPTOKIT))

    def test_each_seal_has_its_own_nonce(self):
        self.assertNotEqual(push.seal(KEY, b"same"), push.seal(KEY, b"same"))


class Token(PushCase):
    """POST /ui/owner/devices/<device>/push: the phone's own token and seal key, from the phone itself."""

    def test_the_feature_is_announced(self):
        features = self.call("/ui/state")[1]["ui_features"]
        self.assertIn("push", features)
        self.assertIn("sealed_push", features)

    def test_the_phone_gives_its_token_and_the_device_list_says_so(self):
        key = self.enrolled()
        status, got = self.give(key)
        self.assertEqual(status, 200, got)
        self.assertEqual((got["device"], got["push"], got["environment"]), ("iphone", True, "production"))
        row = hub.q1("SELECT * FROM owner_device_push WHERE device='iphone'")
        self.assertEqual((row["token"], row["environment"], row["seal"]), (TOKEN, "production", None))
        status, listed = self.call("/ui/owner/devices", source=PHONE, token=key)
        self.assertEqual(status, 200, listed)
        self.assertTrue(listed["devices"][0]["push"])
        status, again = self.give(key, token="cd" * 32, environment="development")      # a new token replaces it
        self.assertEqual(status, 200, again)
        row = hub.q1("SELECT * FROM owner_device_push WHERE device='iphone'")
        self.assertEqual((row["token"], row["environment"]), ("cd" * 32, "development"))
        self.assertNotIn(TOKEN, json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]))

    def test_the_phone_gives_its_seal_key_and_the_command_keeps_only_its_hash(self):
        key = self.enrolled()
        status, got = self.give(key, seal=SEAL)
        self.assertEqual(status, 200, got)
        self.assertEqual(hub.q1("SELECT seal FROM owner_device_push WHERE device='iphone'")["seal"], SEAL)
        kept = json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")])
        self.assertNotIn(SEAL, kept)
        self.assertIn(hashlib.sha256(SEAL.encode()).hexdigest(), kept)
        self.assertNotIn(SEAL, json.dumps([dict(r) for r in hub.q("SELECT * FROM log")]))
        self.give(key)                                                  # an app from before the seal gives none
        self.assertIsNone(hub.q1("SELECT seal FROM owner_device_push WHERE device='iphone'")["seal"])

    def test_only_the_device_itself_gives_its_token(self):
        hub.TEAM["owner_devices"]["ipad"] = {"label": "iPad", "address": OTHER}
        key = self.enrolled()
        status, body = self.give(None, source=MAC)                      # the owner's Mac has no push token
        self.assertEqual(status, 403, body)
        status, body = self.give(key, device="ipad")                    # the phone cannot set the iPad's token
        self.assertEqual(status, 403, body)
        status, body = self.give(None)                                  # the phone without its key
        self.assertEqual((status, body["auth"]), (403, "device_key_required"))
        self.assertIsNone(hub.q1("SELECT 1 FROM owner_device_push"))

    def test_a_bad_token_environment_or_seal_is_refused(self):
        key = self.enrolled()
        for body, why in (({"token": "AB" * 32}, "uppercase"), ({"token": "ab" * 8}, "too short"),
                          ({"token": None}, "missing"), ({"environment": "staging"}, "no such environment"),
                          ({"kinds": ["needs"]}, "an unknown field"),
                          ({"seal": base64.b64encode(bytes(31)).decode()}, "a key of 31 bytes"),
                          ({"seal": "not base64 at all, and not 44 characters"}, "not a key"),
                          ({"seal": 7}, "not text")):
            with self.subTest(why=why):
                self.assertEqual(self.give(key, **body)[0], 400)
        self.assertIsNone(hub.q1("SELECT 1 FROM owner_device_push"))

    def test_the_other_device_routes_stay_on_the_mac(self):
        key = self.enrolled()
        for path in ("/ui/owner/devices", "/ui/owner/devices/iphone/code"):
            with self.subTest(path=path):
                status, body = self.call(path, {"request_id": str(uuid.uuid4()), "db": "test-generation"},
                                         source=PHONE, token=key)
                self.assertEqual((status, body["auth"]), (403, "device_not_allowed"))


class Queue(PushCase):
    """One ping for each device with a token, for each item that the owner is told about, and no text in it."""

    def test_a_raised_item_queues_one_ping_for_each_device_with_a_token(self):
        hub.TEAM["owner_devices"]["ipad"] = {"label": "iPad", "address": OTHER}
        self.give(self.enrolled())                                      # the iPad gives no token
        nid = self.raise_item()
        got = self.pings()
        self.assertEqual([(p["device"], p["kind"], p["item"], p["db"], p["state"]) for p in got],
                         [("iphone", "needs", nid, "test-generation", "queued")])
        self.assertNotIn("domain", json.dumps(got))                     # the row holds no text of the item

    def test_a_removed_device_gets_no_ping(self):
        self.give(self.enrolled())
        del hub.TEAM["owner_devices"]["iphone"]
        self.raise_item()
        self.assertEqual(self.pings(), [])

    def test_a_conversation_item_pings_and_a_deputys_does_not(self):
        self.give(self.enrolled())
        conv = {"id": 1}                                                # the item names it; nothing reads it here
        hub.conversation_need("manager", conv, {"name": "Ana", "role": "customer", "id": 1}, "question", "Refund?",
                              "Ana asks for a refund", "", hub.now())
        self.assertEqual(len(self.pings()), 1)
        hub.conversation_need("manager", conv, {"name": "Bo", "role": hub.PERSON_DECIDES, "id": 2}, "question",
                              "Discount?", "Bo decides a discount", "", hub.now())
        self.assertEqual(len(self.pings()), 1)                          # a deputy decides it; the owner is not rung


class Sender(PushCase):
    """What our side gets, once, and what each of its answers does."""

    def sent(self):
        self.assertTrue(hub.send_ping())
        self.assertFalse(hub.send_ping())                               # nothing is sent twice
        return self.pings()[-1]

    def opened(self, payload):
        """What the phone's extension shows: the sealed part, opened with the phone's own key."""
        return json.loads(push.open_sealed(KEY, base64.b64decode(payload["sealed"])))

    def test_the_ping_goes_through_our_side_with_the_entitlement_and_no_word_of_the_item(self):
        """A fleet that holds an entitlement still sends it as the bearer, as before Founderizer was free."""
        self.give(self.enrolled(), seal=SEAL)
        nid = self.raise_item(options=["Pay €12 now", "Not this year"])
        t0 = hub.now()
        ping = self.sent()
        self.assertEqual((ping["state"], ping["status"], ping["error"]), ("sent", 200, None))
        self.assertEqual(len(self.side.got), 1)
        got = self.side.got[0]
        self.assertEqual(got["path"], "/api/push")
        self.assertEqual(got["headers"]["authorization"], "Bearer " + ENTITLEMENT)
        body = got["body"]
        self.assertEqual((body["token"], body["environment"], body["collapse"]), (TOKEN, "production", f"need-{nid}"))
        self.assertAlmostEqual(body["expires"], t0 + hub.PUSH_KEEP, delta=5)
        payload = body["payload"]
        self.assertEqual({k: v for k, v in payload.items() if k != "sealed"}, {
            "need": nid, "db": "test-generation",
            "aps": {"alert": {"title": "Needs you"}, "sound": "default", "thread-id": "needs", "mutable-content": 1,
                    "badge": 1}})
        for word in ("domain", "€12", "year", "Manager", "card"):      # nothing of the item, readable or not
            self.assertNotIn(word, got["raw"])
        self.assertEqual(self.opened(payload), {"need": nid, "db": "test-generation", "title": "Manager",
                                                "body": "Pay for the domain?",
                                                "options": ["Pay €12 now", "Not this year"]})

    def test_a_phone_without_a_key_gets_the_banner_alone(self):
        self.give(self.enrolled())
        nid = self.raise_item(options=["Pay €12 now", "Not this year"])
        self.assertEqual(self.sent()["state"], "sent")
        self.assertEqual(self.side.got[0]["body"]["payload"], {
            "need": nid, "db": "test-generation",
            "aps": {"alert": {"title": "Needs you"}, "sound": "default", "thread-id": "needs", "badge": 1}})

    def test_the_banner_names_the_agent_that_asks(self):
        """T-39: the banner's title is the asking agent as the apps name it, over its question; "Needs you" only
        for an item that names no agent. Now inside the sealed part, which the phone shows. F16: by its name, also for
        an agent with a role. Bug: the banner says the role again."""
        hub.TEAM["agents"]["atlas"] = {"role": "worker", "runtime": "claude", "machine": "hub",
                                       "title": "Customer Support"}
        need = {"id": 7, "title": "May I restart the production database tonight at 23:00?", "by": "atlas",
                "options": None}
        self.assertEqual({k: v for k, v in self.opened(hub.ping_payload(need, "g", SEAL)).items()
                          if k in ("title", "body")}, {"title": "Atlas", "body": need["title"]})
        self.assertEqual(self.opened(hub.ping_payload(dict(need, by=None), "g", SEAL))["title"], "Needs you")
        # the door's card says the task that asked after its title (owner API 1.160)
        card = dict(need, title="Run one root script on web-1?", door_task="Read the logs")
        self.assertEqual(self.opened(hub.ping_payload(card, "g", SEAL))["body"], "Run one root script on web-1? · Read the logs")
        # as the apps write it (Swift's capitalized), not Python's capitalize() (review A9)
        self.assertEqual(self.opened(hub.ping_payload(dict(need, by="acme-dev"), "g", SEAL))["title"], "Acme-Dev")

    def test_the_door_s_card_of_a_run_gets_no_button_and_a_tap_opens_its_script(self):
        """Owner API 1.247: Run it once signs a root script that a ping does not show, and Full access counts only with
        the owner key on the Mac, so the ping of the door's card of a run carries no buttons, also for a phone from
        before; nor does a GitHub App card or an Add device card (App shell's phone-dead-cards, 22 November 2026). Bug: a
        press on the lock screen signs a script that the owner never saw, or closes a card and starts nothing."""
        card = {"id": 7, "title": "Run one root script on web-1?", "by": "atlas", "door_host": "web-1",
                "options": json.dumps(["Run it once", "Full access on web-1", "No"])}
        said = self.opened(hub.ping_payload(card, "g", SEAL))
        self.assertEqual((said["title"], said["body"]), ("Atlas", "Run one root script on web-1?"))
        self.assertFalse({"options", "no_button"} & set(said))
        for other in (dict(card, door_host=None), {k: v for k, v in card.items() if k != "door_host"}):
            self.assertEqual(self.opened(hub.ping_payload(other, "g", SEAL))["options"],
                             ["Run it once", "Full access on web-1", "No"])
        # a GitHub App card and an Add device card: their first option starts on the Mac (a GitHub page, the Add
        # device picture), so a press of it on the lock screen would close the card and start nothing
        app = {"id": 8, "title": "Make the GitHub App for acme?", "by": "atlas",
               "options": json.dumps(["Make it", "Not now"])}
        for kind in ({"github_app": "acme"}, {"add_device": 1}):
            self.assertNotIn("options", self.opened(hub.ping_payload(dict(app, **kind), "g", SEAL)))
        self.assertEqual(self.opened(hub.ping_payload(dict(app, github_app=None, add_device=0), "g", SEAL))["options"],
                         ["Make it", "Not now"])

    def test_the_managers_reply_under_a_card_rings_as_a_reply_with_no_button(self):
        """Needs clarification (owner API 1.272; the area's review of 20 November 2026): the ring of the manager's reply
        says that it replied, and its first words, and has no options, so that no press on the lock screen answers the
        card and closes it before the owner has read the reply. Bug: the reply rang with the card's own ping, whose
        buttons answer the card and which said nothing of a reply."""
        self.give(self.enrolled(), seal=SEAL)
        hub.TEAM["agents"]["manager"]["title"] = "Customer Support"        # F16: the reply says the name, not the role
        nid = self.raise_item(options=["Pay €12 now", "Not this year"])
        self.sent()
        self.assertIn("options", self.opened(self.side.got[0]["body"]["payload"]))     # the card's own ring
        hub.need_talk_said({"need": nid, "text": "Which one costs less?"})
        hub.t_discuss_need("manager", {"need": f"N-{nid}", "text": "Not this year: nothing is paid until March."})
        ping = self.sent()
        got = self.side.got[1]["body"]
        self.assertEqual((ping["kind"], ping["state"], got["collapse"]), ("talk", "sent", f"need-{nid}"))
        self.assertEqual(self.opened(got["payload"]), {"need": nid, "db": "test-generation",
                                                       "title": "Manager replied about: Pay for the domain?",
                                                       "body": "Not this year: nothing is paid until March."})

    def test_an_option_that_does_not_fit_a_button_opens_the_app(self):
        self.give(self.enrolled(), seal=SEAL)
        fits = "Stop the task and keep what it has written so far."
        self.assertEqual(len(fits), hub.PUSH_BUTTON)
        self.raise_item(options=[fits, "Wait"])
        self.sent()
        self.assertEqual(self.opened(self.side.got[0]["body"]["payload"])["options"], [fits, "Wait"])
        # one character more opens the app. Since owner API 1.380 an agent's option is at most that long too
        # (ADVICE_OPTION_CHARS), and only the hub's own options (a Give, the door's, a team plan's yes) or an item
        # raised before are longer: such an item is put in place as an item raised before is, and pinged as
        # raise_needs_you pings.
        nid = hub.ins("INSERT INTO needs(id,title,why,todo,raised,by,options) VALUES(?,?,?,?,?,?,?)",
                      (hub.unused_id("needs"), "Another", "The card is the owner's", "Press one", hub.now(), "manager",
                       json.dumps([fits + "!", "Wait"])))
        hub.ping_need(nid)
        self.sent()
        self.assertNotIn("options", self.opened(self.side.got[1]["body"]["payload"]))

    def test_an_item_without_options_opens_the_app(self):
        self.give(self.enrolled(), seal=SEAL)
        # A title longer than a notice: since owner feature need_talk only an item written before the 70-character rule
        # has one, so the item is put in place as such an item is, and pinged as raise_needs_you pings.
        nid = hub.ins("INSERT INTO needs(id,title,why,todo,raised,by) VALUES(?,?,?,?,?,?)",
                      (hub.unused_id("needs"), "T" * 300, "The card is the owner's", "Press one", hub.now(), "manager"))
        hub.ping_need(nid)
        self.sent()
        said = self.opened(self.side.got[0]["body"]["payload"])
        self.assertNotIn("options", said)
        self.assertEqual(len(said["body"]), hub.PUSH_TEXT)

    def test_an_item_answered_before_the_ping_goes_gets_none(self):
        """And a reply of the manager's under a card that closed before its ping went gets none either, but for the
        close whose reason is that reply (withdraw_need after the owner's message, owner API 1.316): that one rings.
        Bug: the sender drops the ring of the close that answers his message, because its card is answered, or rings
        an older reply of a card that closed with no word to him."""
        self.give(self.enrolled(), seal=SEAL)
        nid = self.raise_item()
        hub.q("UPDATE needs SET answer='done', answered=? WHERE id=?", (hub.now(), nid))
        ping = self.sent()
        self.assertEqual(ping["state"], "skipped")
        self.assertEqual(self.side.got, [])
        later = self.raise_item("Renew the domain?")
        self.sent()
        hub.need_talk_said({"need": later, "text": "For how long?"})
        hub.t_discuss_need("manager", {"need": f"N-{later}", "text": "One year, as before."})
        hub.t_withdraw_need("manager", {"need": f"N-{later}", "why": "The domain renews by itself."})
        self.assertEqual(self.sent()["state"], "skipped")       # the reply's ring: its card closed with no word to him
        closed = self.raise_item("Pay for the DataFast key?")
        self.sent()
        hub.need_talk_said({"need": closed, "text": "we're no longer using datafast"})
        hub.t_withdraw_need("manager", {"need": f"N-{closed}", "why": "DataFast is out of the site."})
        ping = self.sent()
        self.assertEqual((ping["kind"], ping["state"]), ("talk", "sent"))
        self.assertEqual(self.opened(self.side.got[-1]["body"]["payload"]),
                         {"need": closed, "db": "test-generation", "body": "DataFast is out of the site.",
                          "title": "Manager replied about: Pay for the DataFast key?"})

    def test_a_token_that_apple_calls_gone_is_dropped(self):
        self.give(self.enrolled())
        self.raise_item()
        self.side.answer = (200, {"status": 410, "reason": "Unregistered"})
        ping = self.sent()
        self.assertEqual((ping["state"], ping["status"], ping["error"]), ("failed", 410, "Unregistered"))
        self.assertIsNone(hub.q1("SELECT 1 FROM owner_device_push"))
        self.raise_item(title="A second item")
        self.assertEqual(len(self.pings()), 1)                          # no token, so no ping until the app gives one

    def test_a_fleet_with_no_entitlement_sends_its_ping_with_no_authorization(self):
        """Founderizer is free (the owner, 10 November 2026), and our side's push route asks for no account (the
        website's docs/CONTRACTS.md, "A call with no token"). Until then a fleet with no entitlement sent nothing.
        It sends the same body as a fleet with one, with no Authorization header and no fleet id."""
        hub.q("DELETE FROM entitlement")
        fleet = hub.fleet_id()
        self.give(self.enrolled(), seal=SEAL)
        nid = self.raise_item()
        t0 = hub.now()
        ping = self.sent()
        self.assertEqual((ping["state"], ping["status"], ping["error"]), ("sent", 200, None))
        self.assertEqual(len(self.side.got), 1)
        got = self.side.got[0]
        self.assertEqual(got["path"], "/api/push")
        self.assertNotIn("authorization", got["headers"])
        self.assertEqual((got["headers"]["content-type"], got["headers"]["user-agent"]),
                         ("application/json", "founderizer-hub"))
        body = got["body"]
        self.assertEqual(sorted(body), ["collapse", "environment", "expires", "payload", "token"])
        self.assertEqual((body["token"], body["environment"], body["collapse"]), (TOKEN, "production", f"need-{nid}"))
        self.assertAlmostEqual(body["expires"], t0 + hub.PUSH_KEEP, delta=5)
        self.assertEqual(body["payload"]["aps"]["alert"], {"title": "Needs you"})     # the one banner the route takes
        self.assertEqual(self.opened(body["payload"])["body"], "Pay for the domain?")
        self.assertNotIn(fleet, got["raw"] + json.dumps(got["headers"]))     # and no fleet id anywhere

    def test_a_route_that_asks_for_an_account_is_refused_and_the_phone_keeps_its_token(self):
        """A route that still asks for an account (our side's before the open service) answers 401 or 402: nothing
        went to Apple, so the ping waits, first, for LICENCE_HOLD (push.outcome's table, as for the members' route),
        with one line that names no subscription, and the phone keeps its token."""
        self.give(self.enrolled())
        for status in (401, 402):
            with self.subTest(status=status):
                hub.q("DELETE FROM pings")
                hub._ping_hold["until"] = 0.0
                self.raise_item(title=f"Item {status}")
                self.side.answer = (status, {"error": "lapsed"})
                ping = self.sent()
                self.assertEqual((ping["state"], ping["status"]), ("queued", None))
                self.assertAlmostEqual(hub._ping_hold["until"], hub.now() + push.LICENCE_HOLD, delta=5)
                self.assertEqual(ping["error"], f"127.0.0.1 refused this fleet ({status}), so it sends no pings "
                                                f"for it")
                self.assertIsNotNone(hub.q1("SELECT 1 FROM owner_device_push"))  # our side refused, not Apple
                self.assertEqual(hub._ping_hold["licence"], ENTITLEMENT)     # the entitlement that it refused
                hub.teams_moved()                   # the same entitlement: the hold stays
                self.assertGreater(hub._ping_hold["until"], hub.now() + 60)
                hub.q("UPDATE entitlement SET token=?", (ENTITLEMENT + "x",))   # a new one, also one stored during
                hub.teams_moved()                                               # the call: the hold ends now
                self.assertEqual(hub._ping_hold["until"], 0.0)
                hub.q("UPDATE entitlement SET token=?", (ENTITLEMENT,))

    def test_apples_outage_or_its_refusal_of_our_key_holds_the_owners_ping_and_a_cut_answer_is_unknown(self):
        """Our side's answer is Apple's, inside a 200: Apple's 500 or 503, and its 403 for our side's own key, hold
        the owner's ping, queued and first, for RETRY_DEFAULT, and so do Apple's 429 and our side's own 502; a proxy's
        502 holds it one time (one second send, which can ring twice), and its second makes the row unknown; our
        side's 504 makes it unknown, never sent again, and the next ping waits. Apple's 403 of a development build's
        ping fails it (our side's key is a production key for the app alone, so it never arrives) and holds nothing,
        and the phone keeps its token. Bugs: an Apple outage, or an expired provider key of our side, fails each card's
        ping; a proxy's 502 or 504 after the ping went to Apple sends it twice; a development build's ping is held
        and sent again each minute for a day, and holds its phone or every phone."""
        self.give(self.enrolled())
        for answer, state in (((200, {"status": 500, "reason": "InternalServerError"}), "queued"),
                              ((200, {"status": 503, "reason": "ServiceUnavailable"}), "queued"),
                              ((200, {"status": 403, "reason": "ExpiredProviderToken"}), "queued"),
                              ((502, {"error": "unreachable"}), "queued"),
                              ((502, {"error": "bad_gateway"}), "queued"),
                              ((504, {"error": "gateway"}), "unknown")):
            with self.subTest(answer=answer):
                hub.q("DELETE FROM pings")
                hub._ping_hold["until"] = 0.0
                self.raise_item(title=f"Item {answer[0]}")
                self.side.answer = answer
                ping = self.sent()
                self.assertEqual(ping["state"], state)
                self.assertAlmostEqual(hub._ping_hold["until"], hub.now() + push.RETRY_DEFAULT, delta=5)
                self.assertIsNotNone(hub.q1("SELECT 1 FROM owner_device_push"))
        hub.q("DELETE FROM pings")
        hub._ping_hold["until"] = 0.0
        hub.q("UPDATE owner_device_push SET environment='development'")
        self.raise_item(title="From a development build")
        self.side.answer = (200, {"status": 403, "reason": "BadCertificateEnvironment"})
        ping = self.sent()
        self.assertEqual((ping["state"], ping["error"], hub._ping_hold["until"], hub.PHONE_HOLDS),
                         ("failed", "Apple: 403 BadCertificateEnvironment", 0.0, {}))
        self.assertIsNotNone(hub.q1("SELECT 1 FROM owner_device_push"))

    def test_the_refusals_of_the_open_route_say_what_our_side_said(self):
        """The route that asks for no account has answers of its own (docs/CONTRACTS.md, "Pings to the iPhone app"):
        400 when the alert is not the banner, and 413 for a body over 16384 bytes. The same ping would get the same
        answer again, so it fails with our side's own `says` line, and the phone keeps its token. 429 is below."""
        hub.q("DELETE FROM entitlement")
        self.give(self.enrolled())
        for status, error in ((400, "invalid"), (413, "too_large")):
            with self.subTest(status=status, error=error):
                self.raise_item(title=f"Item {error}")
                self.side.answer = (status, {"error": error, "says": f"the {error} line"})
                ping = self.sent()
                self.assertEqual((ping["state"], ping["status"]), ("failed", None))
                self.assertEqual(ping["error"], f"127.0.0.1 answered {status}: the {error} line")
                self.assertIsNotNone(hub.q1("SELECT 1 FROM owner_device_push"))
                self.assertEqual(hub._ping_hold["until"], 0.0)              # and nothing holds the next ping back
        # a redirect is an answer of its own, and no request goes to the host that it names, which would get the
        # entitlement's bearer and could answer for Apple (urllib's own handler followed a 302 as a GET)
        other = ThreadingHTTPServer(("127.0.0.1", 0), OurSide)
        other.got, other.answer = [], (200, {"status": 200, "reason": ""})
        threading.Thread(target=other.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        try:
            with self.assertRaises(push.PushError) as refused:
                with patch.object(OurSide, "do_POST", lambda handler: (handler.send_response(302),
                        handler.send_header("Location", f"http://127.0.0.1:{other.server_port}/api/push"),
                        handler.send_header("Content-Length", "0"), handler.end_headers())):
                    push.send(hub.CFG["release_channel"], "an-entitlement", "a" * 64, {"aps": {}}, "production")
            self.assertEqual(str(refused.exception), "127.0.0.1 answered 302")
            self.assertEqual(other.got, [])
        finally:
            other.shutdown()
            other.server_close()

    def test_a_ping_that_our_side_holds_back_goes_again_after_its_time_and_reaches_apple_once(self):
        """A count of our side's that is full answers 429 with Retry-After (docs/CONTRACTS.md, "The limits"). Our side
        sent nothing to Apple, so the hub sends the same ping again after that time, as it was and first of the queue,
        and sends no ping before then: our side's count of each caller counts the refused requests too. Apple gets
        the ping once."""
        hub.q("DELETE FROM entitlement")
        self.give(self.enrolled())
        for error in ("too_many", "busy"):
            with self.subTest(error=error):
                first, second = self.raise_item(title=f"First {error}"), self.raise_item(title=f"Second {error}")
                before = len(self.side.got)
                self.side.answer = (429, {"error": error, "says": "a count is full"}, {"Retry-After": "120"})
                t0 = hub.now()
                self.assertTrue(hub.send_ping())
                held = self.pings()[-2]
                self.assertEqual((held["item"], held["state"], held["status"]),  (first, "queued", None))
                self.assertEqual(held["error"], "127.0.0.1 answered 429: a count is full")
                self.assertAlmostEqual(hub._ping_hold["until"], t0 + 120, delta=5)
                self.side.answer = (200, {"status": 200, "reason": ""})
                self.assertFalse(hub.send_ping())                    # nothing goes before the time our side named
                self.assertEqual(len(self.side.got), before + 1)
                hub._ping_hold["until"] = 0.0                        # that time has come
                self.assertTrue(hub.send_ping())
                self.assertTrue(hub.send_ping())
                self.assertFalse(hub.send_ping())
                self.assertEqual([(p["item"], p["state"], p["status"]) for p in self.pings()[-2:]],
                                 [(first, "sent", 200), (second, "sent", 200)])
                self.assertEqual([one["body"]["collapse"] for one in self.side.got[before:]],
                                 [f"need-{first}", f"need-{first}", f"need-{second}"])
                one, again = self.side.got[before]["body"], self.side.got[before + 1]["body"]
                self.assertEqual({k: v for k, v in one.items() if k != "expires"},
                                 {k: v for k, v in again.items() if k != "expires"})           # as it was
                self.assertAlmostEqual(one["expires"], t0 + hub.PUSH_KEEP, delta=5)              # a first try: a day
                self.assertEqual(again["expires"], int(held["created"] + hub.PUSH_KEEP))       # a day after its making
                self.assertIn("; it goes again in 120 seconds",
                              hub.q1("SELECT what FROM log WHERE what LIKE 'ping %: queued%' ORDER BY id DESC")["what"])

    def test_a_held_back_ping_that_would_be_too_old_fails_and_holds_nothing(self):
        """A ping that would be older than a day (PUSH_KEEP) by its next try fails with our side's line, and sets no
        hold: old rows do not drain one for each hold and ring a day late, and the next ping asks for itself."""
        self.give(self.enrolled())
        self.raise_item()
        hub.q("UPDATE pings SET created=?", (hub.now() - hub.PUSH_KEEP + 60,))
        self.side.answer = (429, {"error": "busy", "says": "a count is full"}, {"Retry-After": "120"})
        ping = self.sent()
        self.assertEqual((ping["state"], ping["error"]), ("failed", "127.0.0.1 answered 429: a count is full"))
        self.assertEqual(hub._ping_hold["until"], 0.0)

    def test_a_held_back_ping_whose_day_ended_while_the_hub_was_down_fails_before_it_goes(self):
        """The hold is in memory only, so after a restart a held ping goes at once. When its day ended meanwhile, it
        fails with our side's line before it goes, and our side gets nothing: its expiry would be in the past."""
        self.give(self.enrolled())
        self.raise_item()
        hub.q("UPDATE pings SET error='127.0.0.1 answered 429: a count is full', created=?",
              (hub.now() - hub.PUSH_KEEP - 1,))
        ping = self.sent()
        self.assertEqual((ping["state"], ping["status"], ping["error"]),
                         ("failed", None, "127.0.0.1 answered 429: a count is full"))
        self.assertEqual(self.side.got, [])

    def test_the_sender_looks_again_when_the_hold_ends(self):
        """The sender's thread waits PING_EVERY between two looks at the queue, or less when our side's hold ends
        sooner, so a held-back ping goes on time and not up to PING_EVERY later."""
        self.assertEqual(hub.ping_wait(), hub.PING_EVERY)
        hub._ping_hold["until"] = hub.now() + 5
        self.assertAlmostEqual(hub.ping_wait(), 5, delta=1)
        hub._ping_hold["until"] = hub.now() + 10 * hub.PING_EVERY
        self.assertEqual(hub.ping_wait(), hub.PING_EVERY)
        hub._ping_hold["until"] = hub.now() - 1                 # a hold that ended
        self.assertEqual(hub.ping_wait(), hub.PING_EVERY)

    def test_the_wait_is_what_our_side_said_within_bounds(self):
        """Our side writes Retry-After as whole seconds, for a 429 and a 503, on the owner's route as on the members'.
        A date or no header waits RETRY_DEFAULT, and no wait is shorter than a second or longer than RETRY_MOST (20
        minutes, two of our side's windows). Bug: a long 503 of our side (a switch, a closed shop) brings each fleet's
        call back each minute."""
        for value, seconds in (("120", 120), ("  7 ", 7), (None, push.RETRY_DEFAULT),
                               ("Wed, 21 Oct 2026 07:28:00 GMT", push.RETRY_DEFAULT), ("0", 1), ("-5", 1),
                               ("99999", push.RETRY_MOST)):
            with self.subTest(value=value):
                self.assertEqual(push._retry_after({} if value is None else {"Retry-After": value}), seconds)
        self.side.answer = (429, {"error": "busy", "says": "a count is full"}, {"Retry-After": "30"})
        with self.assertRaises(push.PushError) as refused:
            push.send(hub.CFG["release_channel"], None, TOKEN, {"aps": {"alert": {"title": "Needs you"}}}, "production")
        self.assertEqual((refused.exception.retry_after, str(refused.exception)),
                         (30, "127.0.0.1 answered 429: a count is full"))
        for status in (400, 401, 402, 413, 502, 503):                  # no other refusal is held back
            self.side.answer = (status, {"error": "x"}, {"Retry-After": "30"})
            with self.assertRaises(push.PushError) as refused:
                push.send(hub.CFG["release_channel"], None, TOKEN, {"aps": {}}, "production")
            self.assertEqual(refused.exception.retry_after, 30 if status == 503 else None, status)

    def test_the_banner_is_the_one_alert_our_side_takes(self):
        """A rule of the wire: our side's push route takes a ping only when `aps.alert` is exactly {"title": "Needs
        you"} (the website's BANNER in src/lib/push.ts). A new banner needs that change on the website first."""
        self.assertEqual(hub.PUSH_BANNER, "Needs you")
        for seal in (None, SEAL):
            for by in ("atlas", None):
                need = {"id": 7, "title": "May I restart the database?", "by": by, "options": None}
                with self.subTest(seal=bool(seal), by=by):
                    self.assertEqual(hub.ping_payload(need, "g", seal)["aps"]["alert"], {"title": "Needs you"})

    def test_no_line_of_the_push_names_a_subscription_or_an_entitlement(self):
        """Founderizer has no subscription now, so no line of the hub's own that a ping can fail with names one. (A
        `says` line of our side passes as our side wrote it.)"""
        for status in (400, 401, 402, 403, 404, 413, 429, 500, 502, 503):
            for text in ("", "{}", json.dumps({"says": "a line"})):
                said = push._refusal(status, text, push._side("https://platform.founderizer.com")).lower()
                self.assertNotIn("subscription", said, status)
                self.assertNotIn("entitlement", said, status)

    def test_a_hold_that_is_not_the_licences_stays_when_the_licence_moves_and_each_kind_logs_once_an_hour(self):
        """Our side's 503 holds the owner's pings; a new entitlement (teams_moved) does not end that hold, which is not
        the licence's. A hold that stays logs its first line, then nothing within the hour, then one line with the
        count; another kind of hold has its own first line. Bugs: each hold is taken as the licence's and ends at any
        entitlement; or a hold logs each minute for a day, or never, or hides another kind's first line."""
        self.give(self.enrolled())
        self.raise_item()
        self.side.answer = (503, {"error": "unavailable"})
        self.assertEqual(self.sent()["state"], "queued")
        self.assertIsNone(hub._ping_hold["licence"])
        hub.q("UPDATE entitlement SET token=?", (ENTITLEMENT + "x",))
        hub.teams_moved()
        self.assertGreater(hub._ping_hold["until"], hub.now() + 30)         # the 503's hold stands

        def lines():
            return [r["what"] for r in hub.q("SELECT what FROM log WHERE what LIKE 'ping %: queued%' ORDER BY id")]
        hub._ping_hold["until"] = 0.0
        self.assertTrue(hub.send_ping())                    # the same hold again, within the hour: no line
        self.assertEqual(len(lines()), 1)
        for seen in hub.PING_HELD_LINE.values():
            seen["at"] -= hub.PING_HELD_EVERY + 1           # the hour ends
        hub._ping_hold["until"] = 0.0
        self.assertTrue(hub.send_ping())
        self.assertEqual(len(lines()), 2)
        self.assertIn("(1 more held tries since the last line)", lines()[-1])
        hub._ping_hold["until"] = 0.0
        self.side.answer = (429, {"error": "too_many", "says": "a count is full"}, {"Retry-After": "60"})
        self.assertTrue(hub.send_ping())                    # another kind of hold: its own first line
        self.assertEqual(len(lines()), 3)

    def test_a_proxys_502_holds_a_card_ping_one_time_and_its_second_makes_it_unknown(self):
        """A 502 that is not our side's own (a proxy's, when our side stops at a deploy, maybe after it gave the ping to
        Apple) holds the owner's ping one time; the second such 502 of the same row makes it unknown, never sent again.
        The row keeps the first one (status 502) while it stays queued: through each other hold in between (our
        side's 503, Apple's 429 of that phone) and across a restart; a new row whose id comes back has none. Bugs: the
        row goes again at each hold's end for a day, about 1,440 sends of one card, each with a sound, and each newer
        card waits behind it; or a hold in between writes over the mark, so a 502 and 503 flap rings the phone at each
        502; or each restart sends it once more; or a new row's first proxy 502 makes it unknown at once."""
        self.give(self.enrolled())
        self.raise_item()
        self.side.answer = (502, {"error": "bad_gateway"})
        self.assertEqual((self.sent()["state"], self.pings()[-1]["status"]), ("queued", 502))
        for between in ((503, {"error": "unavailable"}), (200, {"status": 429, "reason": "TooManyRequests"})):
            hub._ping_hold.update(until=0.0, licence=None)
            hub.PHONE_HOLDS.clear()
            self.side.answer = between
            self.assertTrue(hub.send_ping())
            self.assertEqual((self.pings()[-1]["state"], self.pings()[-1]["status"]), ("queued", 502))
        hub._ping_hold.update(until=0.0, licence=None)      # a restart in between: the row keeps its mark
        hub.PHONE_HOLDS.clear()
        hub.settle_pings()
        self.side.answer = (502, {"error": "bad_gateway"})
        self.assertTrue(hub.send_ping())
        self.assertEqual((self.pings()[-1]["state"], len(self.side.got)), ("unknown", 4))
        hub._ping_hold["until"] = 0.0
        self.assertFalse(hub.send_ping())                   # never again
        hub.q("DELETE FROM pings")                          # a row whose id comes back starts with no mark
        hub._ping_hold["until"] = 0.0
        self.raise_item(title="A second card")
        self.assertEqual(self.sent()["state"], "queued")

    def test_a_row_that_goes_during_its_call_lends_its_end_to_no_new_row(self):
        """The card's ping row goes while its call runs (join_items_gone_rows takes the pings of a join item), and a new
        row of a card takes its id: the call's end goes to no row but its own, which is 'sending'. Bug: the new row
        gets the old call's state, 'sent', and its own ping never goes."""
        self.give(self.enrolled())
        self.raise_item()
        old = self.pings()[-1]

        def gone():
            hub.q("DELETE FROM pings WHERE id=?", (old["id"],))
            hub.q("INSERT INTO pings(id,device,kind,item,db,state,created) VALUES(?,?,?,?,?,'queued',?)",
                  (old["id"], old["device"], old["kind"], old["item"], old["db"], hub.now()))
        self.side.during = gone
        self.assertTrue(hub.send_ping())
        self.assertEqual([(r["state"], r["status"], r["error"]) for r in self.pings()], [("queued", None, None)])
        self.side.during = None
        self.assertEqual(self.sent()["state"], "sent")      # the new row's own ping goes
        self.assertEqual(len(self.side.got), 2)

    def test_a_licence_stored_during_the_refused_call_lets_the_next_ping_go_at_once(self):
        """Our side refuses the owner's ping for the licence (401 or 402) while the fleet stores a new entitlement
        during that call: the hold names the entitlement of the call, so the next look sends at once, with no
        teams_moved; and a hold of a call with no entitlement ends at the first one. Bugs: the hold takes the
        entitlement of after the call, or send_ping reads the hold's time alone, and the cards wait 15 minutes with a
        new licence ready."""
        self.give(self.enrolled())
        self.raise_item()
        self.side.during = lambda: hub.q("UPDATE entitlement SET token=?", (ENTITLEMENT + "y",))
        self.side.answer = (401, {"error": "no_licence"})
        self.assertTrue(hub.send_ping())
        self.assertEqual((self.pings()[-1]["state"], hub._ping_hold["licence"]), ("queued", ENTITLEMENT))
        self.side.during, self.side.answer = None, (200, {"status": 200, "reason": ""})
        self.assertTrue(hub.send_ping())
        self.assertEqual(self.pings()[-1]["state"], "sent")
        hub.q("DELETE FROM entitlement")                    # no entitlement at all: the hold names none
        self.raise_item(title="A second card")
        self.side.answer = (402, {"error": "lapsed"})
        self.assertEqual(self.sent()["state"], "queued")
        self.assertEqual(hub._ping_hold["licence"], "")
        hub.q("INSERT INTO entitlement(id,fleet,token,plan,until,machines,agents,verified,stored) "
              "VALUES(1,'0f1e2d3c4b5a6978',?,'founder-monthly',?,5,10,1,?)",
              (ENTITLEMENT, hub.now() + 86400, hub.now()))
        self.assertEqual(hub.owner_hold_until(), 0.0)       # the first entitlement ends it
        hub._ping_hold.update(until=hub.now() - 1, licence=ENTITLEMENT)
        self.assertEqual((hub.owner_hold_until(), hub._ping_hold["licence"]), (0.0, None))     # its time ended

    def test_apples_429_holds_only_that_phone_and_a_development_ping_takes_the_same_table(self):
        """Apple's 429 (too many pings to that phone) holds only that phone's pings, its log line says when it goes
        again, and the other phone's ping goes at once. A development build's ping takes the same table: our side's
        429 queues it again, and Apple's 410 drops its token. Bugs: one
        phone's 429 holds every phone of the owner; or a development ping is lost at our side's 429, or keeps a token
        that Apple called gone and goes to it again."""
        hub.TEAM["owner_devices"]["ipad"] = {"label": "iPad", "address": OTHER}     # a second phone of the owner
        self.give(self.enrolled())
        self.give(self.enrolled("ipad", OTHER), device="ipad", source=OTHER, token="cd" * 32)
        hub.q("DELETE FROM pings")
        self.raise_item()                                   # one row for each phone
        rows = {r["device"]: r["id"] for r in hub.q("SELECT id, device FROM pings")}
        self.side.answer = (200, {"status": 429, "reason": "TooManyRequests"})
        self.assertTrue(hub.send_ping())                    # the first phone's: held
        self.assertEqual((hub._ping_hold["until"], sorted(hub.PHONE_HOLDS)),
                         (0.0, [min(rows, key=rows.get)]))
        self.assertIn(f"it goes again in {push.RETRY_DEFAULT} seconds",
                      hub.q1("SELECT what FROM log WHERE what LIKE 'ping %: queued%' ORDER BY id DESC")["what"])
        self.side.answer = (200, {"status": 200, "reason": ""})
        self.assertTrue(hub.send_ping())                    # the other phone's goes at once
        self.assertFalse(hub.send_ping())                   # and the held one waits
        states = {r["device"]: r["state"] for r in hub.q("SELECT device, state FROM pings")}
        self.assertEqual(sorted(states.values()), ["queued", "sent"])
        hub.PHONE_HOLDS.clear()
        self.assertTrue(hub.send_ping())                    # its hold ended
        hub.q("DELETE FROM pings")
        hub.q("UPDATE owner_device_push SET environment='development'")
        self.raise_item(title="From development builds")
        first = self.pings()[0]["device"]
        self.side.answer = (429, {"error": "too_many", "says": "a count is full"}, {"Retry-After": "30"})
        self.assertTrue(hub.send_ping())
        self.assertEqual((self.pings()[0]["state"], hub._ping_hold["until"] > hub.now() + 20), ("queued", True))
        hub._ping_hold["until"] = 0.0
        self.side.answer = (200, {"status": 410, "reason": "Unregistered"})
        self.assertTrue(hub.send_ping())
        self.assertEqual(self.pings()[0]["state"], "failed")
        self.assertEqual([r["device"] for r in hub.q("SELECT device FROM owner_device_push")],
                         [d for d in ("iphone", "ipad") if d != first])    # only that phone's token went

    def test_a_fault_of_the_senders_wait_ends_no_thread(self):
        """A read fault in ping_wait (it reads the records while a hold of the licence stands), also after a fault of
        the look itself, is reported, and the thread waits PING_EVERY and goes on. Bug: the thread that sends every
        owner ping dies for the life of the process, and member pings stop too."""
        class Stop(BaseException):
            pass

        class Wake:
            def wait(self, seconds=None):
                raise Stop(seconds)

            def set(self):
                pass

            def clear(self):
                pass

        def fault(*args):
            raise RuntimeError("a read fault")
        with patch.object(hub, "send_ping", fault), patch.object(hub, "ping_wait", fault), \
                patch.object(hub, "PING_WAKE", Wake()), patch.object(hub, "print_fault"):
            with self.assertRaises(Stop) as stopped:
                hub.ping_sender()
        self.assertEqual(stopped.exception.args, (hub.PING_EVERY,))

    def test_the_hold_log_keeps_at_most_64_kinds(self):
        """The log of the held owner pings keeps at most 64 kinds of hold in memory. Bug: an endless run of new kinds
        grows the map for the life of the process."""
        hub.PING_HELD_LINE.update({f"kind {i}": {"n": 0, "at": hub.now()} for i in range(64)})
        self.give(self.enrolled())
        self.raise_item()
        self.side.answer = (503, {"error": "unavailable"})
        self.assertEqual(self.sent()["state"], "queued")
        self.assertEqual(len(hub.PING_HELD_LINE), 1)

    def test_our_side_out_of_reach_sends_nothing_and_the_ping_waits(self):
        """No connection to our side: nothing went to Apple, so the ping waits, first, for RETRY_DEFAULT."""
        self.give(self.enrolled())
        self.raise_item()
        hub.CFG["release_channel"] = "http://127.0.0.1:1"
        ping = self.sent()
        self.assertEqual(ping["state"], "queued")
        self.assertAlmostEqual(hub._ping_hold["until"], hub.now() + push.RETRY_DEFAULT, delta=5)
        self.assertIn("cannot be reached", ping["error"])

    def test_no_answer_from_our_side_is_unknown_and_never_sent_again(self):
        self.give(self.enrolled())
        self.raise_item()
        quiet = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
        quiet.stop, quiet.block_on_close = threading.Event(), False
        # a short poll: its shutdown() below waits for the loop's next look, which was up to 0.5 s
        threading.Thread(target=quiet.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        try:
            with patch.object(push, "TIMEOUT", 1):
                hub.CFG["release_channel"] = f"http://127.0.0.1:{quiet.server_port}"
                ping = self.sent()
        finally:
            quiet.stop.set()
            quiet.shutdown()
            quiet.server_close()
        self.assertEqual((ping["state"], ping["status"]), ("unknown", 0))

    def test_a_ping_that_was_sending_when_the_hub_stopped_is_unknown(self):
        self.give(self.enrolled())
        self.raise_item()
        hub.q("UPDATE pings SET state='sending'")
        hub.settle_pings()
        self.assertEqual(self.pings()[0]["state"], "unknown")
        self.assertFalse(hub.send_ping())
        self.assertEqual(self.side.got, [])


class Present(Sender):
    """Quiet phone (plan section 10): while the owner's Mac app says that he is at it, a Needs-you ping waits in the
    queue, and it goes when his presence ends, if its item is still open. Only the Mac's reads count."""

    def setUp(self):
        super().setUp()
        hub.PRESENT.clear()             # in memory: none comes from another test
        self.addCleanup(hub.PRESENT.clear)

    def read_state(self, source=MAC, token=None, present=True):
        return self.call("/ui/state", source=source, token=token,
                         headers={"X-Fleet-Present": "1"} if present else None)

    def later(self, seconds):
        real = hub.now
        return patch.object(hub, "now", lambda: real() + seconds)

    def test_a_ping_waits_while_the_owner_is_at_the_mac_and_goes_when_he_leaves(self):
        self.give(self.enrolled())
        self.raise_item()
        self.assertEqual(self.read_state()[0], 200)
        self.assertGreater(hub.owner_present_until(), hub.now())
        self.assertFalse(hub.send_ping())
        self.assertEqual([p["state"] for p in self.pings()], ["queued"])
        self.assertLessEqual(hub.ping_wait(), hub.PRESENCE_HOLD)        # the sender looks again when presence ends
        with self.later(hub.PRESENCE_HOLD + 1):
            self.assertEqual(hub.owner_present_until(), 0.0)
            self.assertEqual(hub.ping_wait(), hub.PING_EVERY)
            self.assertTrue(hub.send_ping())
        self.assertEqual(self.pings()[0]["state"], "sent")
        self.assertEqual(len(self.side.got), 1)

    def test_an_item_answered_while_he_is_at_the_mac_never_rings(self):
        self.give(self.enrolled())
        nid = self.raise_item()
        self.read_state()
        self.assertFalse(hub.send_ping())
        hub.q("UPDATE needs SET answer='Pay it', answered=? WHERE id=?", (hub.now(), nid))
        with self.later(hub.PRESENCE_HOLD + 1):
            self.assertTrue(hub.send_ping())
        self.assertEqual((self.pings()[0]["state"], self.pings()[0]["error"]),
                         ("skipped", "the item was answered before the ping went"))
        self.assertEqual(self.side.got, [])

    def test_an_app_that_sends_no_header_and_a_phone_that_sends_it_change_nothing(self):
        key = self.enrolled()
        self.give(key)
        self.raise_item()
        self.assertEqual(self.read_state(present=False)[0], 200)        # an older Mac app
        self.read_state(source=PHONE, token=key)                        # a phone's read, whatever it answers
        self.read_state(source=OTHER)                                   # an address that is no owner's
        self.assertEqual(hub.owner_present_until(), 0.0)
        self.assertEqual(self.sent()["state"], "sent")

    def test_a_mac_read_with_a_bearer_token_is_refused_and_sets_no_presence(self):
        status, body = self.read_state(token="not-a-device-key")
        self.assertEqual((status, body.get("auth")), (403, "key_not_expected"))
        self.assertEqual(hub.PRESENT, {})
        self.assertEqual(hub.owner_present_until(), 0.0)

    def test_a_hub_restart_forgets_presence_and_the_held_ping_goes(self):
        self.give(self.enrolled())
        self.raise_item()
        self.read_state()
        self.assertFalse(hub.send_ping())
        hub.PRESENT.clear()                                             # what a restart of the hub leaves
        self.assertEqual(self.sent()["state"], "sent")


class Badge(PushCase):
    """The number on the app's icon (the owner's yes of 12 November 2026, point 1): the count of what needs him, in
    each Needs-you ping, and alone in a push with no word when it changes and no Needs-you ping carries it."""

    def setUp(self):
        super().setUp()
        hub.PRESENT.clear()
        self.addCleanup(hub.PRESENT.clear)

    def drain(self):
        """What the sender thread does at each wake: every ping that may go, then a look at each icon's number."""
        while hub.send_ping() or hub.badge_look():
            pass

    def badges(self):
        """What our side got of the badge-only pushes, in order."""
        return [one["body"]["payload"] for one in self.side.got if "alert" not in one["body"]["payload"]["aps"]]

    def badge_rows(self):
        return [(p["item"], p["state"], p["error"]) for p in self.pings() if p["kind"] == "badge"]

    def answer(self, nid):
        hub.q("UPDATE needs SET answer='Pay it', answered=? WHERE id=?", (hub.now(), nid))

    def test_the_count_is_the_tabs_open_items_and_tasks_only_he_can_move(self):
        """The twin of MobileStore.needsYouCount: open items, and each task once whose stop was not confirmed or whose
        unknown outcome no agent can check (checker 'owner', as the apps read it: TaskOutcome.waitsOnOwner). An
        answered item, a known outcome, a released hold, and an unknown outcome that a session of its task's agent
        checks first ('') or that the hub gave an agent above it (the owner, 23 November 2026: "this sohuld be
        automatically reattempted or reviewed by the agents!") are not counted, whatever holds or ends its task."""
        self.assertEqual(hub.owner_count(), 0)
        first, _ = self.raise_item(), self.raise_item(title="Second")
        self.answer(first)
        t0 = hub.now()
        for task, state, owner in ((20, "working", "open"), (21, "submitted", "manager"), (22, "working", "manager"),
                                   (23, "failed", "manager"), (24, "working", "closed")):
            hub.q("INSERT INTO tasks(id,title,owner,requester,state,created,needs,attempt) "
                  "VALUES(?,'Work',?,'manager',?,?,'none',2)", (task, owner, state, t0))
        for task, state, resolved, checker in ((7, "unknown", None, "owner"), (7, "unknown", None, "owner"),
                                               (8, "unknown", t0, "owner"), (9, "done", None, "owner"),
                                               (13, "unknown", None, "owner"), (20, "unknown", None, ""),
                                               (21, "unknown", None, "manager"), (22, "unknown", None, "manager"),
                                               (23, "unknown", None, "lead"), (24, "unknown", None, "manager")):
            hub.q("INSERT INTO outcomes(task,attempt,hold,tool_call_id,state,created,resolved,checker) "
                  "VALUES(?,1,0,?,?,?,?,?)", (task, uuid.uuid4().hex, state, t0, resolved, checker))
        for task, state, released, by in ((7, "not_confirmed", None, "owner"), (10, "not_confirmed", None, "owner"),
                                          (11, "not_confirmed", t0, "owner"), (12, "stopped", None, "owner"),
                                          (22, "stopped", None, "owner")):
            hub.q("INSERT INTO holds(task,kind,by,state,created,attempt,released) VALUES(?,'stop',?,?,?,1,?)",
                  (task, by, state, t0, released))
        # one open item; tasks 7 and 10, and 13, whose outcome no agent can check; not the held 22, the ended 23 or
        # the Shell-off 24, whose agents above check them, nor 20, whose own agent checks it
        self.assertEqual(hub.owner_count(), 1 + 3)
        hub.q("UPDATE outcomes SET checker='owner' WHERE task=22")      # the manager left its line unread
        self.assertEqual(hub.owner_count(), 1 + 4)
        with patch.object(hub, "PUSH_BADGE_MOST", 2):
            self.assertEqual(hub.owner_count(), 2)                      # never more than our side takes

    def test_each_needs_you_ping_carries_the_count(self):
        self.give(self.enrolled(), seal=SEAL)
        self.raise_item()
        self.raise_item(title="Second")
        self.drain()
        self.assertEqual([one["body"]["payload"]["aps"]["badge"] for one in self.side.got], [2, 2])
        self.assertEqual(self.badges(), [])                             # the pings carried it: no badge-only push
        self.assertEqual(hub.q1("SELECT badge FROM owner_device_push")["badge"], 2)

    def test_an_answer_sends_the_new_number_alone_once(self):
        self.give(self.enrolled(), seal=SEAL)
        nid = self.raise_item()
        self.drain()
        self.answer(nid)
        self.drain()
        self.drain()
        sent = self.side.got[-1]["body"]
        self.assertEqual(sent["payload"], {"aps": {"badge": 0}})        # no banner, no sound, no sealed part
        self.assertEqual((sent["collapse"], sent["expires"]), ("badge", 0))     # Apple keeps none for a phone that is off
        self.assertEqual(self.badges(), [{"aps": {"badge": 0}}])
        self.assertEqual([(p["kind"], p["item"], p["state"]) for p in self.pings()],
                         [("needs", nid, "sent"), ("badge", 0, "sent")])

    def test_one_badge_push_waits_for_each_phone_and_goes_with_the_number_of_then(self):
        self.give(self.enrolled(), seal=SEAL)
        items = [self.raise_item(title=f"Item {n}") for n in range(3)]
        self.drain()
        self.answer(items[0])
        self.assertTrue(hub.badge_look())
        self.answer(items[1])
        self.assertTrue(hub.badge_look())                               # the waiting one takes the new number
        self.assertFalse(hub.badge_look())
        self.assertEqual(self.badge_rows(), [(1, "queued", None)])
        self.drain()
        self.assertEqual(self.badges(), [{"aps": {"badge": 1}}])

    def test_a_needs_you_ping_that_waits_carries_the_new_number(self):
        self.give(self.enrolled(), seal=SEAL)
        self.raise_item()
        self.drain()
        self.raise_item(title="Second")                                 # 2 now, and its ping waits
        self.assertFalse(hub.badge_look())
        self.drain()
        self.assertEqual(self.badges(), [])
        self.assertEqual(self.side.got[-1]["body"]["payload"]["aps"]["badge"], 2)

    def test_a_badge_push_goes_after_the_needs_you_pings(self):
        self.give(self.enrolled(), seal=SEAL)
        first = self.raise_item()
        self.drain()
        self.answer(first)
        self.assertTrue(hub.badge_look())                               # 0 waits
        second = self.raise_item(title="Second")                        # 1 again, in a ping queued after it
        self.drain()
        self.assertEqual([one["body"]["payload"].get("need") for one in self.side.got], [first, second])
        self.assertEqual(self.badge_rows(), [(1, "skipped", "the icon shows that number already")])

    def test_the_owner_at_the_mac_holds_the_ping_and_not_the_number(self):
        self.give(self.enrolled(), seal=SEAL)
        first = self.raise_item()
        self.drain()
        self.call("/ui/state", headers={"X-Fleet-Present": "1"})
        self.raise_item(title="Second")
        self.answer(first)
        self.raise_item(title="Third")                                  # 2 now; both pings wait
        self.drain()
        self.assertEqual(self.badges(), [{"aps": {"badge": 2}}])
        self.assertEqual([p["state"] for p in self.pings() if p["kind"] == "needs"], ["sent", "queued", "queued"])

    def test_a_site_that_refuses_the_shape_ends_badge_pushes_and_no_ping_waits_for_it(self):
        """The relay from before badge-only pushes answers 400 to {"aps": {"badge": n}} (aps.alert is not the banner).
        The hub then sends none until it starts again, and the next Needs-you ping goes as before."""
        self.give(self.enrolled(), seal=SEAL)
        first = self.raise_item()
        self.drain()
        self.answer(first)
        self.side.answer = (400, {"error": "invalid", "says": "aps.alert must be the banner"})
        self.drain()
        self.assertTrue(hub.BADGE["off"])
        self.side.answer = (200, {"status": 200, "reason": ""})
        before = len(self.side.got)
        second = self.raise_item(title="Second")
        self.answer(second)
        third = self.raise_item(title="Third")
        self.drain()
        self.assertEqual([one["body"]["payload"].get("need") for one in self.side.got[before:]], [third])
        self.assertEqual(hub._ping_hold["until"], 0.0)

    def test_a_held_back_badge_push_holds_back_no_needs_you_ping(self):
        self.give(self.enrolled(), seal=SEAL)
        first = self.raise_item()
        self.drain()
        self.answer(first)
        self.side.answer = (429, {"error": "too_many", "says": "a count is full"}, {"Retry-After": "120"})
        self.drain()
        self.assertEqual([row[:2] for row in self.badge_rows()], [(0, "queued")])
        self.assertEqual(hub._ping_hold["until"], 0.0)
        self.assertGreater(hub.BADGE["until"], hub.now() + 100)
        self.assertLessEqual(hub.ping_wait(), 120)
        self.side.answer = (200, {"status": 200, "reason": ""})
        second = self.raise_item(title="Second")
        self.drain()
        self.assertEqual(self.side.got[-1]["body"]["payload"]["need"], second)      # it went at once
        hub.BADGE["until"] = 0.0                                        # that time has come
        self.drain()
        self.assertEqual(self.badge_rows(), [(1, "skipped", "the icon shows that number already")])

    def test_a_number_that_did_not_get_through_is_not_tried_again_until_it_changes(self):
        self.give(self.enrolled(), seal=SEAL)
        first, second = self.raise_item(), self.raise_item(title="Second")
        self.drain()
        self.answer(first)
        self.side.answer = (502, {"error": "unreachable", "says": "Apple cannot be reached"})
        self.drain()
        self.assertFalse(hub.badge_look())                              # no loop
        self.side.answer = (200, {"status": 200, "reason": ""})
        self.answer(second)
        self.drain()
        self.assertEqual(self.badges(), [{"aps": {"badge": 1}}, {"aps": {"badge": 0}}])

    def test_a_phone_with_no_token_and_a_new_token(self):
        key = self.enrolled()
        self.raise_item()
        self.drain()
        self.assertEqual(self.side.got, [])                             # no token, nothing
        self.give(key)
        self.drain()
        self.assertEqual(self.badges(), [{"aps": {"badge": 1}}])        # a new token: its number is not known
        self.give(key)                                                  # the same token at the next start
        self.drain()
        self.assertEqual(len(self.badges()), 1)

    def test_the_sender_wakes_when_the_records_change(self):
        hub.PING_WAKE.clear()
        self.raise_item()
        self.assertTrue(hub.PING_WAKE.is_set())



class MemberRoute(PushCase):
    """B9: a ping to a member's phone goes by our side's member route (push.send_member), with the fleet's licence, and
    a 429 there names the count that is full (the website's docs/CONTRACTS.md, "Pings to a phone of a company's
    people"). The owner's route stays as it was."""

    PAYLOAD = {"aps": {"alert": {"loc-key": "shared-reply"}, "mutable-content": 1}, "sealed": "AAAA"}

    def member(self, **extra):
        return push.send_member(hub.CFG["release_channel"], ENTITLEMENT, SEALED, self.PAYLOAD, **extra)

    def refusal(self, call):
        with self.assertRaises(push.PushError) as refused:
            call()
        return refused.exception

    def test_each_answer_has_one_class_in_the_table(self):
        """push.outcome classes each answer once, for both routes: held (nothing went to Apple, a cause of the fleet or
        of a service), phone, may have gone, the ping's own fault, sent. Bugs: a 502 or an Apple outage drops pings;
        a 504 after the ping went sends it twice; a refusal of the token keeps the token."""
        E = push.PushError
        held, phone, maybe, refused, sent = push.HELD, push.PHONE, push.MAYBE, push.REFUSED, push.SENT
        D, L = push.RETRY_DEFAULT, push.LICENCE_HOLD
        table = [
            (dict(error=E("x", status=502, word="unreachable")), (held, D, False, False)),
            (dict(error=E("x", status=502)), (held, D, False, False)),                  # the owner's route
            (dict(error=E("x", status=502), member=True), (maybe, D, False, False)),
            (dict(error=E("x", status=502, word="bad_gateway"), member=True), (maybe, D, False, False)),
            (dict(error=E("x", status=502, word="unreachable"), member=True), (held, D, False, False)),
            (dict(error=E("x", status=410, gone=True), member=True), (refused, None, False, True)),
            (dict(error=E("x", status=410, gone=True)), (refused, None, False, False)),
            (dict(error=E("x", status=410), member=True), (refused, None, False, False)),
            (dict(error=E("x", status=405)), (held, D, False, False)),
            (dict(error=E("x", status=408)), (held, D, False, False)),
            (dict(error=E("x", status=421)), (held, D, False, False)),
            (dict(error=E("x", status=425)), (held, D, False, False)),
            (dict(error=E("x", status=426)), (held, D, False, False)),
            (dict(error=E("x", status=431)), (held, D, False, False)),
            (dict(error=E("x", status=503, retry_after=7)), (held, 7, False, False)),
            (dict(error=E("x", status=401)), (held, L, True, False)),
            (dict(error=E("x", status=402)), (held, L, True, False)),
            (dict(error=E("x", status=429, retry_after=30, full="fleet")), (held, 30, False, False)),
            (dict(error=E("x", status=429, retry_after=30, full="phone")), (phone, 30, False, False)),
            (dict(error=E("cannot be reached")), (held, D, False, False)),
            (dict(error=E("x", setting="channel")), (held, D, False, False)),
            (dict(error=E("x", setting="bearer")), (held, L, True, False)),
            (dict(error=E("x", status=301)), (held, D, False, False)),
            (dict(error=E("x", status=403)), (held, D, False, False)),
            (dict(error=E("x", status=404)), (held, D, False, False)),
            (dict(error=E("x", status=500)), (maybe, D, False, False)),
            (dict(error=E("x", status=504)), (maybe, D, False, False)),
            (dict(error=E("x", status=599)), (maybe, D, False, False)),
            (dict(error=E("x", status=400)), (refused, None, False, False)),
            (dict(error=E("x", status=413)), (refused, None, False, False)),
            (dict(error=E("x", status=422)), (refused, None, False, False)),
            (dict(error=E("x", local=True)), (refused, None, False, True)),
            (dict(status=200, reason=""), (sent, None, False, False)),
            (dict(status=0, reason="no answer"), (maybe, D, False, False)),
            (dict(status=429, reason="TooManyRequests"), (phone, D, False, False)),
            (dict(status=500, reason="InternalServerError"), (held, D, False, False)),
            (dict(status=503, reason="ServiceUnavailable"), (held, D, False, False)),
            (dict(status=403, reason="ExpiredProviderToken"), (held, D, False, False)),
            (dict(status=403, reason="ExpiredProviderToken", environment="production"), (held, D, False, False)),
            (dict(status=403, reason="BadCertificateEnvironment", environment="development"),
             (refused, None, False, False)),
            (dict(status=410, reason="Unregistered", environment="development"), (refused, None, False, True)),
            (dict(status=429, reason="TooManyProviderTokenUpdates"), (held, D, False, False)),
            (dict(status=403, reason="InvalidProviderToken"), (held, D, False, False)),
            (dict(status=403, reason="BadCertificateEnvironment"), (held, D, False, False)),
            (dict(status=410, reason="Unregistered"), (refused, None, False, True)),
            (dict(status=400, reason="BadDeviceToken"), (refused, None, False, True)),
            (dict(status=400, reason="DeviceTokenNotForTopic"), (refused, None, False, True)),
            (dict(status=400, reason="PayloadEmpty"), (refused, None, False, False)),
            (dict(status=413, reason="PayloadTooLarge"), (refused, None, False, False)),
            (dict(status=403, reason="Forbidden"), (held, D, False, False)),
            (dict(status=403, reason="UnrelatedKeyIdInToken", environment="production"), (held, D, False, False)),
            (dict(status=403, reason="Forbidden", environment="development"), (refused, None, False, False)),
        ]
        for given, (kind, wait, licence, gone) in table:
            with self.subTest(given=str(given)):
                got = push.outcome(**given)
                self.assertEqual((got.kind, got.wait, got.licence, got.token_gone), (kind, wait, licence, gone))

    def test_an_answer_that_never_comes_whole_is_no_answer_and_never_a_fault(self):
        """A 200 whose chunked body is cut, or a status line that is no HTTP, after the ping went out: (0, no answer),
        on the member route and on the owner's, as for a time-out; a body of JSON too deep to read is a bad body, not
        a fault. Bugs: http.client's own fault, or the JSON reader's, gets out of push.py, so the ping thread sends the
        member ping again, and the owner's row stays 'sending' until a restart."""
        class Broken(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                if self.server.cut == "deep":       # a whole body of JSON too deep to read
                    body = b"[" * 100000
                    self.send_response(self.server.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.server.cut:
                    self.send_response(self.server.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.send_header("Retry-After", "45")
                    self.end_headers()
                    self.wfile.write(b"20\r\n{\"status\":200")       # a chunk of 32 bytes, cut after 13
                else:
                    self.wfile.write(b"NO HTTP AT ALL\r\n\r\n")
                self.wfile.flush()
                self.close_connection = True

            def log_message(self, *_args):
                pass
        side = ThreadingHTTPServer(("127.0.0.1", 0), Broken)
        threading.Thread(target=side.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.addCleanup(side.server_close)
        self.addCleanup(side.shutdown)
        channel = f"http://127.0.0.1:{side.server_port}"
        for cut in (True, False):
            side.cut, side.status = cut, 200
            with self.subTest(cut=cut):
                for send in (lambda: push.send_member(channel, ENTITLEMENT, SEALED, self.PAYLOAD),
                             lambda: push.send(channel, None, TOKEN, {"aps": {}}, "production")):
                    status, reason = send()
                    self.assertEqual((status, reason), (0, "127.0.0.1 gave no answer in time"))
        # a 429 whose body is cut: still our side's refusal, with the time of its head
        side.cut, side.status = True, 429
        for send in (lambda: push.send_member(channel, ENTITLEMENT, SEALED, self.PAYLOAD),
                     lambda: push.send(channel, None, TOKEN, {"aps": {}}, "production")):
            e = self.refusal(send)
            self.assertEqual((e.status, e.retry_after), (429, 45))
        # a body of JSON too deep to read: a 200 is an answer that is not Apple's, a 429 our side's refusal
        side.cut, side.status = "deep", 200
        self.assertEqual(push.send_member(channel, ENTITLEMENT, SEALED, self.PAYLOAD),
                         (0, "127.0.0.1 answered with something other than Apple's answer"))
        side.status = 429
        e = self.refusal(lambda: push.send_member(channel, ENTITLEMENT, SEALED, self.PAYLOAD))
        self.assertEqual((e.status, e.full), (429, "fleet"))

    def test_a_channel_or_a_bearer_that_cannot_go_into_a_request_is_a_refusal_of_the_setting(self):
        """An address that no request can go to (no http or https, no host, a host that IDNA does not take, a user or
        a password, a % in the host, a port that is no number, a character that is not ASCII, a space, a control
        character or DEL), or a licence with a line break: push.py refuses before anything goes out, as a setting of
        the fleet (setting "channel" or "bearer"), never as the ping's own fault (local), on both routes. Bugs:
        http.client's fault before the request reads as "it went, no answer"; or a bad setting drops each ping."""
        before = len(self.side.got)
        good = hub.CFG["release_channel"]
        cases = [(c, ENTITLEMENT, "channel") for c in (
            "http://127.0.0.1:port", good + "/a b", good + chr(7), good + chr(0x7f), "ftp://127.0.0.1/",
            "http:///path", "http://a..b/", "https://u:p@127.0.0.1/", "http://127.0.0.1%3A80/", good + "/" + chr(0xe9))]
        cases.append((good, ENTITLEMENT + "\r\nX-Other: 1", "bearer"))
        for channel, bearer, setting in cases:
            with self.subTest(channel=channel, bearer=bearer[-12:]):
                for send in (lambda: push.send_member(channel, bearer, SEALED, self.PAYLOAD),
                             lambda: push.send(channel, bearer, TOKEN, {"aps": {}}, "production")):
                    e = self.refusal(send)
                    self.assertEqual((e.setting, e.local), (setting, False))
        self.assertEqual(len(self.side.got), before)

    def test_a_410_gone_of_the_member_route_says_so(self):
        """Our side's 410 {"gone": true} on the member route (a value that does not belong to the fleet, or does not
        open): PushError.gone. Bug: the hub reads it as any 4xx, keeps the link's token, and each later ping to it gets
        410 again and counts in the fleet's 600."""
        for body, gone in (({"gone": True}, True), ({"gone": "yes"}, False), ({"error": "x"}, False)):
            with self.subTest(body=body):
                self.side.answer = (410, body)
                e = self.refusal(lambda: push.send_member(hub.CFG["release_channel"], ENTITLEMENT,
                                                          SEALED, self.PAYLOAD))
                self.assertEqual((e.status, e.gone), (410, gone))
        self.side.answer = (410, {"gone": True})            # the owner's route has no such answer
        self.assertFalse(self.refusal(lambda: push.send(hub.CFG["release_channel"], None, TOKEN, {"aps": {}},
                                                        "production")).gone)

    def test_a_502_says_whether_it_is_our_sides_own(self):
        """Our side's own 502 has the body {"error": "unreachable"} (Apple could not be reached): PushError.word says
        so, and a proxy's 502 has no such word. Bug: every 502 is taken as our side's, and a proxy's 502 after the ping
        went to Apple sends it again."""
        for body, word in (({"error": "unreachable", "says": "Apple could not be reached"}, "unreachable"),
                           ({"error": "bad_gateway"}, "bad_gateway"), ({"nothing": 1}, None)):
            with self.subTest(word=word):
                self.side.answer = (502, body)
                e = self.refusal(lambda: push.send_member(hub.CFG["release_channel"], ENTITLEMENT,
                                                          SEALED, self.PAYLOAD))
                self.assertEqual((e.status, e.word), (502, word))
                self.assertEqual(str(e), "127.0.0.1 could not reach Apple's push service" if word == "unreachable"
                                 else "127.0.0.1 answered 502")     # a proxy's 502 does not claim it

    def test_push_gives_the_name_of_the_full_count_of_a_429_and_a_member_ping_goes_by_its_own_route(self):
        """Bugs: the hub reads no count from a 429, so a full count of one phone holds back the member pings of every
        phone of the fleet, or a full count of the fleet holds back none; a member ping goes to /api/push, which
        refuses the member form, or with no licence; a member ping carries Apple's token or its environment in the
        clear (b9-phone-members.md 10.7), or a value of another form goes out; a 503 of the member route (its switch, a
        closed shop) gives no
        time, so its ping is lost or sent again at once; a refusal of push.py's own checks reads as one of our side,
        so the sender holds every ping for it in place of dropping the one that can never go; or no licence, or no
        network, reads as such a refusal, and each ping that meets it is dropped."""
        self.assertEqual(self.member(collapse="c" * 32, expires=123), (200, ""))
        got = self.side.got[-1]
        self.assertEqual((got["path"], got["headers"]["authorization"]), ("/api/push/member", "Bearer " + ENTITLEMENT))
        self.assertEqual(got["body"], {"push": SEALED, "payload": self.PAYLOAD, "collapse": "c" * 32, "expires": 123})
        self.assertNotIn('"token"', got["raw"])         # no token and no environment in the clear (b9 10.7)
        self.assertNotIn('"environment"', got["raw"])
        for full, named in (("phone", "phone"), ("members", "members"), ("fleet", "fleet"), ("galaxy", "fleet"),
                            (None, "fleet")):
            with self.subTest(full=full):
                body = dict({"error": "too_many", "says": "a count is full"}, **({"full": full} if full else {}))
                self.side.answer = (429, body, {"Retry-After": "45"})
                e = self.refusal(self.member)
                self.assertEqual((e.full, e.retry_after, e.status), (named, 45, 429))
        self.side.answer = (429, {"error": "busy", "full": "phone"}, {"Retry-After": "45"})
        e = self.refusal(lambda: push.send(hub.CFG["release_channel"], None, TOKEN, {"aps": {}}, "production"))
        self.assertEqual((e.full, e.retry_after), (None, 45))               # the owner's route names no count
        self.side.answer = (503, {"error": "unavailable"}, {"Retry-After": "600"})
        self.assertEqual((self.refusal(self.member).retry_after, self.refusal(self.member).full), (600, None))
        self.side.answer = (503, {"error": "unavailable"})                  # no APNs key at our side: no time
        self.assertIsNone(self.refusal(self.member).retry_after)
        self.assertFalse(self.refusal(self.member).local)                  # our side refused it: it went out
        before = len(self.side.got)
        e = self.refusal(lambda: push.send_member(hub.CFG["release_channel"], None, SEALED, self.PAYLOAD))
        self.assertEqual((len(self.side.got), e.status, e.local), (before, None, False))     # no licence: it waits
        tokens = member_tokens()
        for value in [TOKEN, None, "v1.test0key." + "A" * 447, *(tokens["not_push"].values() if tokens else ())]:
            e = self.refusal(lambda: push.send_member(hub.CFG["release_channel"], ENTITLEMENT, value, self.PAYLOAD))
            self.assertEqual((e.local, len(self.side.got)), (True, before))
        for one in (tokens["valid"] + tokens["refused"]) if tokens else ():     # each value of the phone's form goes
            self.assertTrue(push.member_push(one["push"]), one["name"])
        e = self.refusal(lambda: push.send_member("http://127.0.0.1:1", ENTITLEMENT, SEALED, self.PAYLOAD))
        self.assertIn("cannot be reached", str(e))
        self.assertIs(e.local, False)           # an outage of the network: each ping waits, none is dropped


if __name__ == "__main__":
    unittest.main()

"""Pings to the owner's phone (MOBILE-APP.md 9, owner feature push): the phone's push token and its seal key, one
ping for each new Needs-you item, what our side carries, and the states of a ping. A local hub with a test source
address for the Mac and the phone, and a stand-in for our side's push route (founderizer.com /api/push) on loopback.
No real device, key, network or AI call."""
import base64
import hashlib
import inspect
import json
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import hub
import push
from test_mobile import MAC, OTHER, PHONE, Devices

TOKEN = "ab" * 32                                   # a device token as Apple gives it: 32 bytes in hexadecimal
KEY = bytes(range(32))                              # the phone's own seal key
SEAL = base64.b64encode(KEY).decode()
ENTITLEMENT = "eyJmbGVldCI6IjBmMWUyZDNjNGI1YTY5NzgifQ.c2lnbmVk"


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from test_mobile, whose own tests stay in their own file."""
    suite = unittest.TestSuite()
    for cls in (Seal, Token, Queue, Sender, Present, Badge):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class OurSide(BaseHTTPRequestHandler):
    """Our side's push route, as far as the hub can tell: it keeps what it was sent and answers server.answer, which
    is Apple's answer in a 200, or a refusal of its own, and the headers of a third element if there is one."""
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.got.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()},
                                "body": json.loads(body), "raw": body.decode()})
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
        threading.Thread(target=self.side.serve_forever, daemon=True).start()
        hub.CFG["release_channel"] = f"http://127.0.0.1:{self.side.server_port}"
        hub.q("INSERT INTO entitlement(id,fleet,token,plan,until,machines,agents,verified,stored) "
              "VALUES(1,'0f1e2d3c4b5a6978',?,'founder-monthly',?,5,10,1,?)", (ENTITLEMENT, hub.now() + 86400, hub.now()))
        hub._ping_hold["until"] = 0.0           # a hold is in memory: none comes from another test
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
                                                          "what_to_do": "Press one"}, **extra))
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

    def test_no_token_no_ping(self):
        self.enrolled()
        self.raise_item()
        self.assertEqual(self.pings(), [])

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
        for an item that names no agent. Now inside the sealed part, which the phone shows."""
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

    def test_an_option_that_does_not_fit_a_button_opens_the_app(self):
        self.give(self.enrolled(), seal=SEAL)
        fits = "Stop the task and keep what it has written so far."
        self.assertEqual(len(fits), hub.PUSH_BUTTON)
        self.raise_item(options=[fits, "Wait"])
        self.sent()
        self.assertEqual(self.opened(self.side.got[0]["body"]["payload"])["options"], [fits, "Wait"])
        self.raise_item(title="Another", options=[fits + "!", "Wait"])      # one character more opens the app
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
        self.give(self.enrolled())
        nid = self.raise_item()
        hub.q("UPDATE needs SET answer='done', answered=? WHERE id=?", (hub.now(), nid))
        ping = self.sent()
        self.assertEqual(ping["state"], "skipped")
        self.assertEqual(self.side.got, [])

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
        """A route that still asks for an account (our side's before the open service) answers 401 or 402. The ping
        fails with one line that names no subscription, and Apple was not asked, so the phone keeps its token."""
        self.give(self.enrolled())
        for status in (401, 402):
            with self.subTest(status=status):
                self.raise_item(title=f"Item {status}")
                self.side.answer = (status, {"error": "lapsed"})
                ping = self.sent()
                self.assertEqual((ping["state"], ping["status"]), ("failed", None))
                self.assertEqual(ping["error"], f"founderizer.com refused this fleet ({status}), so it sends no pings "
                                                f"for it")
                self.assertIsNotNone(hub.q1("SELECT 1 FROM owner_device_push"))  # our side refused, not Apple

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
                self.assertEqual(ping["error"], f"founderizer.com answered {status}: the {error} line")
                self.assertIsNotNone(hub.q1("SELECT 1 FROM owner_device_push"))
                self.assertEqual(hub._ping_hold["until"], 0.0)              # and nothing holds the next ping back

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
                self.assertEqual(held["error"], "founderizer.com answered 429: a count is full")
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

    def test_a_held_back_ping_that_would_be_too_old_fails_and_the_queue_still_waits(self):
        """A ping that would be older than a day (PUSH_KEEP) by its next try fails with our side's line, and the next
        ping still waits for the time that our side named, because our side would hold it back too."""
        self.give(self.enrolled())
        self.raise_item()
        hub.q("UPDATE pings SET created=?", (hub.now() - hub.PUSH_KEEP + 60,))
        self.side.answer = (429, {"error": "busy", "says": "a count is full"}, {"Retry-After": "120"})
        ping = self.sent()
        self.assertEqual((ping["state"], ping["error"]), ("failed", "founderizer.com answered 429: a count is full"))
        self.assertGreater(hub._ping_hold["until"], hub.now())

    def test_a_held_back_ping_whose_day_ended_while_the_hub_was_down_fails_before_it_goes(self):
        """The hold is in memory only, so after a restart a held ping goes at once. When its day ended meanwhile, it
        fails with our side's line before it goes, and our side gets nothing: its expiry would be in the past."""
        self.give(self.enrolled())
        self.raise_item()
        hub.q("UPDATE pings SET error='founderizer.com answered 429: a count is full', created=?",
              (hub.now() - hub.PUSH_KEEP - 1,))
        ping = self.sent()
        self.assertEqual((ping["state"], ping["status"], ping["error"]),
                         ("failed", None, "founderizer.com answered 429: a count is full"))
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
        self.assertIn("PING_WAKE.wait(ping_wait())", inspect.getsource(hub.ping_sender))

    def test_the_wait_is_what_our_side_said_within_bounds(self):
        """Our side writes Retry-After as whole seconds. A date or no header waits RETRY_DEFAULT, and no wait is
        shorter than a second or longer than RETRY_MOST (20 minutes, two of our side's windows)."""
        for value, seconds in (("120", 120), ("  7 ", 7), (None, push.RETRY_DEFAULT),
                               ("Wed, 21 Oct 2026 07:28:00 GMT", push.RETRY_DEFAULT), ("0", 1), ("-5", 1),
                               ("99999", push.RETRY_MOST)):
            with self.subTest(value=value):
                self.assertEqual(push._retry_after({} if value is None else {"Retry-After": value}), seconds)
        self.side.answer = (429, {"error": "busy", "says": "a count is full"}, {"Retry-After": "30"})
        with self.assertRaises(push.PushError) as refused:
            push.send(hub.CFG["release_channel"], None, TOKEN, {"aps": {"alert": {"title": "Needs you"}}}, "production")
        self.assertEqual((refused.exception.retry_after, str(refused.exception)),
                         (30, "founderizer.com answered 429: a count is full"))
        for status in (400, 401, 402, 413, 502, 503):                  # no other refusal is held back
            self.side.answer = (status, {"error": "x"}, {"Retry-After": "30"})
            with self.assertRaises(push.PushError) as refused:
                push.send(hub.CFG["release_channel"], None, TOKEN, {"aps": {}}, "production")
            self.assertIsNone(refused.exception.retry_after, status)

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
                said = push._refusal(status, text).lower()
                self.assertNotIn("subscription", said, status)
                self.assertNotIn("entitlement", said, status)

    def test_our_side_out_of_reach_sends_nothing(self):
        self.give(self.enrolled())
        self.raise_item()
        hub.CFG["release_channel"] = "http://127.0.0.1:1"
        ping = self.sent()
        self.assertEqual(ping["state"], "failed")
        self.assertIn("cannot be reached", ping["error"])

    def test_no_answer_from_our_side_is_unknown_and_never_sent_again(self):
        self.give(self.enrolled())
        self.raise_item()
        quiet = ThreadingHTTPServer(("127.0.0.1", 0), Quiet)
        quiet.stop, quiet.block_on_close = threading.Event(), False
        threading.Thread(target=quiet.serve_forever, daemon=True).start()
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
        """The twin of MobileStore.needsYouCount: open items, and each task once whose outcome is not known or whose
        stop was not confirmed. An answered item, a known outcome and a released hold are not counted."""
        self.assertEqual(hub.owner_count(), 0)
        first, _ = self.raise_item(), self.raise_item(title="Second")
        self.answer(first)
        t0 = hub.now()
        for task, state, resolved in ((7, "unknown", None), (7, "unknown", None), (8, "unknown", t0), (9, "done", None)):
            hub.q("INSERT INTO outcomes(task,attempt,hold,tool_call_id,state,created,resolved) VALUES(?,1,0,?,?,?,?)",
                  (task, uuid.uuid4().hex, state, t0, resolved))
        for task, state, released in ((7, "not_confirmed", None), (10, "not_confirmed", None),
                                      (11, "not_confirmed", t0), (12, "stopped", None)):
            hub.q("INSERT INTO holds(task,kind,by,state,created,attempt,released) VALUES(?,'stop','owner',?,?,1,?)",
                  (task, state, t0, released))
        self.assertEqual(hub.owner_count(), 1 + 2)                      # one open item; tasks 7 and 10
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


if __name__ == "__main__":
    unittest.main()

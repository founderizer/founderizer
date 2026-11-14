"""The owner's phone (MOBILE-APP.md): owner devices with their own key, the enrollment code, the routes that a
device may use, and the compact reads with their ETag. A local hub with a test source address for the owner's Mac and
for the phone. No real network, device, key or AI call. The team.json save itself is the existing owner save
(save_integration), which its own tests cover; these checks use hub.TEAM, as the owner API 1.12 checks do.

The compact read builds its answer from its own moment of the records since 11 November 2026, as GET /ui/state does
(hub.state_moment): MobileMoment holds it with the records in WAL mode, as the hub opens them. The other checks keep
their records in MEMORY journal mode, so they read the phone's page under the hub's lock, as before."""
import ast
import hashlib
import inspect
import json
import re
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from unittest.mock import patch

import hub
from test_ui_api import PATIENCE, OwnerAPI

PHONE, OTHER = "127.0.0.5", "127.0.0.6"         # the owner's phone, and a second device
MAC = "127.0.0.1"                               # the owner's Mac, as OwnerAPI sets it
T0 = 1794322671.5               # MobileMoment: the hub's clock stands still, so two reads of a page are the same bytes
LOGIN = "Pr4ct!ce-Login#2026"   # MobileMoment: a registered login, inside a text of each part of the phone's page
LATER = "L4ter-Login!9090"      # MobileMoment: registered while the phone's page is built
PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(64))  # a file that the phone sends with a message


class Devices(OwnerAPI):
    """The hub side, through the real routes."""

    def setUp(self):
        super().setUp()
        hub.TEAM["owner_devices"] = {"iphone": {"label": "iPhone", "address": PHONE}}

    # ---- helpers
    def call(self, path, body=None, source=MAC, token=None, headers=None):
        head = dict({"Content-Type": "application/json", "X-Fleet-Client": "deterministic-test"}, **(headers or {}))
        if token is not None:
            head["Authorization"] = "Bearer " + token
        return self.request(path, body, headers=head, source=source)

    def raw(self, path, source=MAC, token=None, headers=None):
        """The status, the headers and the body, so that a 304 without a body can be checked."""
        head = dict({"Accept": "application/json", "X-Test-Source": source}, **(headers or {}))
        if token is not None:
            head["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.base + path, headers=head)
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with op.open(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as r:
            with r:
                return r.code, dict(r.headers), r.read()

    def code(self, device="iphone", **body):
        return self.call(f"/ui/owner/devices/{device}/code",
                         dict({"request_id": str(uuid.uuid4()), "db": "test-generation"}, **body))

    def enroll(self, code, source=PHONE):
        return self.call("/ui/owner/enroll", {"code": code}, source=source)

    def enrolled(self, device="iphone", source=PHONE):
        """The owner makes one code on the Mac; the device takes its key with it, once."""
        status, made = self.code(device)
        self.assertEqual(status, 200, made)
        status, got = self.enroll(made["code"], source=source)
        self.assertEqual(status, 200, got)
        return got["key"]

    def task(self, title="Work", state="working", owner="manager", details="d" * 2000):
        return hub.ins("INSERT INTO tasks(title,details,done_when,owner,requester,state,created,needs,attempt) "
                       "VALUES(?,?,?,?,?,?,?,'none',1)",
                       (title, details, "it is done", owner, "manager", state, hub.now()))

    def message(self, agent="manager", text="A goal"):
        event = hub.emit(agent, "chat", text)
        hub.ins("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient) "
                "VALUES(?,'message',?,?,?,'deterministic-test',?)", (str(uuid.uuid4()), text, event, hub.now(), agent))
        return event

    def report(self, agent="manager", text="A reply"):
        return hub.ins("INSERT INTO owner_reports(text,about,created,agent) VALUES(?,'',?,?)",
                       (text, hub.now(), agent))

    def upload(self, data=PNG, source=PHONE, token=None):
        """POST /ui/attachments with the raw bytes, as the phone's MobileClient.upload sends them."""
        head = {"Content-Type": "image/png", "X-Fleet-Client": "deterministic-test", "X-Fleet-Name": "shot.png",
                "X-Fleet-Request-Id": str(uuid.uuid4()), "X-Test-Source": source}
        if token is not None:
            head["Authorization"] = "Bearer " + token
        req = urllib.request.Request(self.base + "/ui/attachments?db=test-generation", data=data, headers=head,
                                     method="POST")
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with op.open(req, timeout=PATIENCE) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as r:
            with r:
                return r.code, json.load(r)

    # ---- team.json: what an owner device may be
    def test_validate_team_takes_a_device_and_refuses_a_bad_one(self):
        team = {"addresses": {"owner": MAC, "hub": "127.0.0.2"}, "hub": {"machine": "hub"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}},
                "owner_devices": {"iphone": {"label": "iPhone", "address": PHONE}}}
        hub.validate_team(team)                                                     # a device is accepted
        for devices, why in (
                ({"iphone": {"label": "iPhone"}}, "a device without an address"),
                ({"iphone": {"label": "iPhone", "address": "not-an-address"}}, "an address that is not one"),
                ({"iphone": {"label": "iPhone", "address": MAC}}, "the address of a machine"),
                ({"iphone": {"label": "", "address": PHONE}}, "an empty label"),
                ({"iphone": {"label": "x\ny", "address": PHONE}}, "a label on two lines"),
                ({"IPHONE": {"label": "iPhone", "address": PHONE}}, "a name that is not a device name"),
                ({"iphone": {"label": "iPhone", "address": PHONE, "push": True}}, "an unknown field"),
                ({"iphone": {"label": "iPhone", "address": PHONE},
                  "ipad": {"label": "iPad", "address": PHONE}}, "two devices with one address"),
                ({f"d{n}": {"label": f"D{n}", "address": f"127.0.1.{n}"} for n in range(5)}, "more than four devices")):
            with self.subTest(why=why):
                with self.assertRaises(ValueError):
                    hub.validate_team(dict(team, owner_devices=devices))

    def test_no_agent_may_sit_on_a_device_address(self):
        team = {"addresses": {"owner": MAC, "hub": "127.0.0.2", "box": PHONE}, "hub": {"machine": "hub"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                           "worker": {"role": "worker", "runtime": "codex", "machine": "box", "can": []}},
                "owner_devices": {"iphone": {"label": "iPhone", "address": PHONE}}}
        with self.assertRaises(ValueError):
            hub.validate_team(team)

    # ---- the owner's Mac keeps its rule
    def test_the_owner_mac_reads_without_a_token_and_is_refused_with_one(self):
        self.assertEqual(self.call("/ui/mobile")[0], 200)
        status, body = self.call("/ui/mobile", token="whatever")
        self.assertEqual((status, body["auth"]), (403, "key_not_expected"))

    def test_the_feature_is_announced(self):
        self.assertIn("mobile", self.call("/ui/state")[1]["ui_features"])

    # ---- enrollment
    def test_a_device_without_a_key_cannot_read_and_enrolls_with_one_code(self):
        status, body = self.call("/ui/mobile", source=PHONE)
        self.assertEqual((status, body["auth"]), (403, "device_not_enrolled"))
        key = self.enrolled()
        self.assertEqual(self.call("/ui/mobile", source=PHONE, token=key)[0], 200)
        self.assertEqual(hub.q1("SELECT sha256 FROM owner_devices WHERE device='iphone'")["sha256"],
                         hub.hashlib.sha256(key.encode()).hexdigest())

    def test_a_code_works_once_and_only_from_its_device(self):
        status, made = self.code()
        self.assertEqual(status, 200)
        self.assertEqual(self.enroll(made["code"])[0], 200)
        status, again = self.enroll(made["code"])                       # the same code a second time
        self.assertEqual((status, again["error"]), (403, "that code is not valid"))

    def test_only_a_device_address_may_enroll(self):
        status, made = self.code()
        status, body = self.enroll(made["code"], source=OTHER)          # an address that is not a device
        self.assertEqual(status, 403)
        self.assertIn("owner_devices", body["error"])
        self.assertIsNone(hub.q1("SELECT 1 FROM owner_devices"))

    def test_a_browser_origin_never_enrolls(self):
        status, made = self.code()
        # an Origin of another site is refused before any route, as on every write (devops task 1.1)
        status, body = self.call("/ui/owner/enroll", {"code": made["code"]}, source=PHONE,
                                 headers={"Origin": "http://localhost"})
        self.assertEqual((status, body["error"]), (403, "foreign origin"))
        # and the hub's own Origin still meets the route's own rule: no browser enrolls
        status, body = self.call("/ui/owner/enroll", {"code": made["code"]}, source=PHONE,
                                 headers={"Origin": self.base})
        self.assertEqual((status, body["error"]), (403, "browser origins are not accepted"))

    def test_five_wrong_codes_stop_the_device_for_an_hour(self):
        self.code()
        for _ in range(5):
            self.assertEqual(self.enroll("AAAA-BBBB")[0], 403)
        status, body = self.enroll("AAAA-BBBB")
        self.assertEqual(status, 429, body)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM owner_device_tries")["n"], 5)

    def test_the_hub_keeps_no_code_and_no_key(self):
        status, made = self.code()
        key = self.enroll(made["code"])[1]["key"]
        kept = hub.q1("SELECT result FROM ui_controls WHERE route='owner/devices/iphone/code'")["result"]
        self.assertIsNone(json.loads(kept)["code"])                     # a repeat of the command gives no code
        rows = json.dumps([dict(r) for r in hub.q("SELECT * FROM owner_device_codes")])
        self.assertNotIn(made["code"].replace("-", ""), rows)
        self.assertNotIn(key, rows)
        log = json.dumps([dict(r) for r in hub.q("SELECT * FROM log")])
        for secret in (key, made["code"], made["code"].replace("-", "")):
            self.assertNotIn(secret, log)
        self.assertNotIn(key, json.dumps(self.call("/ui/owner/devices")[1]))

    def test_a_new_key_replaces_the_old_one(self):
        first = self.enrolled()
        second = self.enrolled()
        self.assertNotEqual(first, second)
        self.assertEqual(self.call("/ui/mobile", source=PHONE, token=first)[1]["auth"], "device_key_mismatch")
        self.assertEqual(self.call("/ui/mobile", source=PHONE, token=second)[0], 200)

    # ---- the key rules of a device
    def test_a_device_needs_its_own_key_on_every_read(self):
        key = self.enrolled()
        for token, auth in ((None, "device_key_required"), ("", "device_key_mismatch"),
                            ("another-key", "device_key_mismatch")):
            with self.subTest(auth=auth):
                status, body = self.call("/ui/mobile", source=PHONE, token=token)
                self.assertEqual((status, body["auth"]), (403, auth))
        headers = {"Authorization": "Basic " + key}                     # a header that is not a bearer token
        self.assertEqual(self.call("/ui/mobile", source=PHONE, headers=headers)[1]["auth"], "device_key_mismatch")

    def test_a_refused_request_shows_that_the_phone_reached_the_hub(self):
        self.assertEqual(self.call("/ui/mobile", source=PHONE)[1]["auth"], "device_not_enrolled")
        row = self.call("/ui/owner/devices")[1]["devices"][0]
        self.assertIsNone(row["last_seen"])                             # it read nothing: it has no key
        self.assertEqual(row["last_answer"], "device_not_enrolled")     # but the hub heard it
        self.assertGreater(row["last_contact"], 0)
        key = self.enrolled()
        self.assertEqual(self.call("/ui/mobile", source=PHONE, token=key)[0], 200)
        row = self.call("/ui/owner/devices")[1]["devices"][0]
        self.assertGreater(row["last_seen"], 0)                         # now it read
        self.assertIsNone(row["last_answer"])                           # and the hub refused nothing
        self.assertEqual(self.call("/ui/mobile", source=PHONE, token="wrong")[1]["auth"], "device_key_mismatch")
        self.assertEqual(self.call("/ui/owner/devices")[1]["devices"][0]["last_answer"], "device_key_mismatch")

    def test_a_device_that_never_arrives_has_no_contact(self):
        self.enrolled()
        row = self.call("/ui/owner/devices")[1]["devices"][0]
        self.assertIsNone(row["last_contact"])                          # enrollment is not a device request
        self.assertIsNone(row["last_seen"])

    def test_the_owner_removes_a_device_and_it_is_refused_at_once(self):
        key = self.enrolled()
        self.assertEqual(self.call("/ui/mobile", source=PHONE, token=key)[0], 200)
        hub.q("DELETE FROM owner_devices WHERE device='iphone'")        # what save_owner_device does on a removal
        self.assertEqual(self.call("/ui/mobile", source=PHONE, token=key)[1]["auth"], "device_not_enrolled")
        hub.TEAM["owner_devices"] = {}                                  # and the device leaves team.json
        status, body = self.call("/ui/mobile", source=PHONE, token=key)
        self.assertEqual(status, 403)
        self.assertIn("is not owner's machine", body["error"])      # not a device and not the Mac

    def test_a_device_reads_its_own_routes_only(self):
        key = self.enrolled()
        for path in ("/ui/mobile", "/ui/mobile/chat/manager", "/ui/state", "/ui/owner/devices"):
            with self.subTest(path=path):
                self.assertEqual(self.call(path, source=PHONE, token=key)[0], 200)
        for path in ("/ui/team", "/ui/machines", "/ui/capacity", "/ui/secrets/salts", "/ui/secrets/same", "/ui/people"):
            with self.subTest(path=path):
                status, body = self.call(path, source=PHONE, token=key)
                self.assertEqual((status, body["auth"]), (403, "device_not_allowed"))

    def test_a_device_writes_a_message_but_never_the_team(self):
        key = self.enrolled()
        status, receipt = self.call("/ui/messages", self.command(text="A goal from the phone"), source=PHONE, token=key)
        self.assertEqual(status, 200, receipt)
        self.assertEqual(hub.q1("SELECT client FROM ui_requests WHERE request_id=?",
                                (receipt["request_id"],))["client"], "deterministic-test")
        for path in ("/ui/owner/devices", "/ui/team/google", "/ui/knowledge"):
            with self.subTest(path=path):
                status, body = self.call(path, {"request_id": str(uuid.uuid4()), "db": "test-generation"},
                                         source=PHONE, token=key)
                self.assertEqual(status, 403, body)

    def test_a_device_sends_a_file_and_reads_the_same_bytes_from_its_chat(self):
        """The phone's client sends a file before its message and reads it from the chat (MobileClient.upload and
        .attachment). A device reads only a file that a message carries: an upload alone is in none of its reads."""
        key = self.enrolled()
        status, sent = self.upload(token=key)
        self.assertEqual(status, 200, sent)
        self.assertEqual((sent["size"], sent["sha256"]), (len(PNG), hashlib.sha256(PNG).hexdigest()))
        path = f"/ui/attachments/{sent['id']}?db=test-generation"
        self.assertEqual(self.raw(path, source=PHONE, token=key)[0], 404)       # no message carries it yet
        self.assertEqual(self.raw(path)[2], PNG)                                # the owner's Mac reads it as before
        status, receipt = self.call("/ui/messages", self.command(text="", attachments=[sent["id"]]), source=PHONE,
                                    token=key)
        self.assertEqual(status, 200, receipt)
        status, chat = self.call("/ui/mobile/chat/manager", source=PHONE, token=key)
        self.assertEqual(status, 200, chat)
        self.assertEqual([[f["id"] for f in i["attachments"]] for i in chat["items"]], [[sent["id"]]])
        status, headers, data = self.raw(path, source=PHONE, token=key)
        self.assertEqual((status, data), (200, PNG))
        self.assertEqual(headers["X-Fleet-SHA256"], sent["sha256"])
        self.assertEqual(self.raw(f"/ui/attachments/{sent['id'] + 1}?db=test-generation", source=PHONE,
                                  token=key)[0], 404)

    def test_a_device_never_keeps_a_file_and_its_key_is_checked_on_each_file_route(self):
        key = self.enrolled()
        status, sent = self.upload(token=key)
        self.assertEqual(status, 200, sent)
        self.assertEqual(self.call("/ui/messages", self.command(attachments=[sent["id"]]), source=PHONE,
                                   token=key)[0], 200)
        keep = f"/ui/attachments/{sent['id']}/keep"
        mark = lambda: {"request_id": str(uuid.uuid4()), "db": "test-generation", "keep": True}
        status, body = self.call(keep, mark(), source=PHONE, token=key)
        self.assertEqual((status, body["auth"]), (403, "device_not_allowed"))   # it writes the owner's knowledge
        self.assertIsNone(hub.q1("SELECT kept FROM attachments WHERE id=?", (sent["id"],))["kept"])
        status, body = self.call(keep, mark())                                  # the route is there, on the Mac
        self.assertEqual(status, 200, body)
        files = hub.q1("SELECT COUNT(*) AS n FROM attachments")["n"]
        for token, auth in ((None, "device_key_required"), ("wrong-key", "device_key_mismatch")):
            with self.subTest(auth=auth):
                status, body = self.upload(token=token)
                self.assertEqual((status, body["auth"]), (403, auth))
                status, _, data = self.raw(f"/ui/attachments/{sent['id']}?db=test-generation", source=PHONE,
                                           token=token)
                self.assertEqual((status, json.loads(data)["auth"]), (403, auth))
        self.assertEqual(hub.q1("SELECT COUNT(*) AS n FROM attachments")["n"], files)  # no file came in
        self.assertEqual([hub.device_may(path, method) for method, path in (
            ("POST", "/ui/attachments"), ("GET", "/ui/attachments/3"), ("POST", "/ui/attachments/3/keep"),
            ("GET", "/ui/attachments"), ("POST", "/ui/attachments/3"), ("GET", "/ui/attachments/3/keep"))],
            [True, True, False, False, False, False])

    def test_a_message_from_the_phone_says_via_iphone_and_names_no_device(self):
        """T3 Code idea 5: the agent reads that a message came from the phone, as the class only. The Mac's message
        and an answer to a Needs-you item keep their words, and a client label alone gives no mark."""
        hub.TEAM["owner_devices"] = {"iphone-2": {"label": "iPhone 2", "address": PHONE}}
        hub.TEAM["addresses"]["dev-host"] = "127.0.0.9"
        hub.TEAM["agents"]["dev-lead"] = {"role": "worker", "runtime": "claude", "machine": "dev-host", "can": []}
        key = self.enrolled("iphone-2")
        text = lambda receipt: hub.q1("SELECT text FROM events WHERE id=?", (receipt["event_id"],))["text"]
        status, boss = self.call("/ui/messages", self.command(text="A goal from the phone"), source=PHONE, token=key)
        self.assertEqual(status, 200, boss)
        self.assertEqual(text(boss), "[owner via iPhone] A goal from the phone")
        body = self.command(recipient="dev-lead", text="Look at the build")
        status, worker = self.call("/ui/messages", body, source=PHONE, token=key)
        self.assertEqual(status, 200, worker)
        self.assertEqual(text(worker), f"[owner chat request_id={body['request_id']} via=iPhone] Look at the build")
        edit = self.command(recipient="dev-lead", text="Look at the tests", replaces_request_id=body["request_id"])
        status, edited = self.call("/ui/messages", edit, source=PHONE, token=key)
        self.assertTrue(edited["edited"], edited)
        self.assertEqual(text(worker), f"[owner chat request_id={body['request_id']} via=iPhone] Look at the tests")
        for said in (text(boss), text(worker)):
            self.assertNotIn("iPhone 2", said)
            self.assertNotIn("iphone-2", said)
            self.assertNotIn("deterministic-test", said)
        status, mac = self.call("/ui/messages", self.command(text="From the Mac"),
                                headers={"X-Fleet-Client": "founderizer-ios/1/00000000-0000-4000-8000-000000000000"})
        self.assertEqual(status, 200, mac)
        self.assertEqual(text(mac), "[owner] From the Mac")
        nid = self.need()
        status, answer = self.call(f"/ui/needs/{nid}", {"request_id": str(uuid.uuid4()), "db": "test-generation", "answer": "Yes"}, source=PHONE, token=key)
        self.assertEqual(status, 200, answer)
        self.assertTrue(text(answer).startswith(f"[owner] Answer to Needs-you N-{nid} "), text(answer))

    # ---- the devices page of the Mac
    def test_the_mac_sees_each_device_its_key_and_its_open_code(self):
        status, before = self.call("/ui/owner/devices")
        self.assertEqual(status, 200)
        self.assertEqual([d["device"] for d in before["devices"]], ["iphone"])
        self.assertEqual((before["devices"][0]["key"], before["devices"][0]["this_device"]), (False, False))
        self.code()
        self.enrolled()
        row = self.call("/ui/owner/devices")[1]["devices"][0]
        self.assertTrue(row["key"] and row["since"] and row["label"] == "iPhone" and row["address"] == PHONE)
        self.assertIsNone(row["code_expires"])                          # the enrollment used the open code
        self.assertNotIn("sha256", row)

    def test_a_code_for_an_unknown_device_is_refused(self):
        status, body = self.code("ipad")
        self.assertEqual((status, body["error"]), (404, "no such owner device"))

    # ---- a phone added with a code alone (device_by_code: Add device shows the QR at once)
    def new_code(self, source=MAC, token=None):
        return self.call("/ui/owner/devices/code", {"request_id": str(uuid.uuid4()), "db": "test-generation"},
                         source=source, token=token)

    def team_saves(self, devices):
        """The team.json save is save_integration's, which its own tests cover: here it edits hub.TEAM, after the same
        validate_team, and a refusal of it is the same 400."""
        hub.TEAM = dict(hub.TEAM, hub={"machine": "hub"}, owner_devices=devices)

        def save(base, change, message, by="owner"):
            team = json.loads(json.dumps(hub.TEAM))
            if not change(team):
                return {"changed": False}
            try:
                hub.validate_team(team)
            except ValueError as e:
                raise hub.Refusal(400, str(e)) from None
            hub.TEAM = team
            return {"changed": True}
        return patch.object(hub, "save_integration", save)

    def test_the_feature_of_a_code_alone_is_announced(self):
        self.assertIn("device_by_code", self.call("/ui/state")[1]["ui_features"])

    def test_a_new_phone_enrolls_with_a_code_alone_from_its_own_address(self):
        with self.team_saves({}):
            status, made = self.new_code()
            self.assertEqual((status, made["device"]), (200, None), made)
            status, got = self.enroll(made["code"])
            self.assertEqual((status, got["device"], got["label"]), (200, "iphone", "iPhone"), got)
            self.assertEqual(hub.TEAM["owner_devices"], {"iphone": {"label": "iPhone", "address": PHONE}})
            self.assertEqual(self.call("/ui/mobile", source=PHONE, token=got["key"])[0], 200)
            status, again = self.enroll(made["code"], source=OTHER)     # the code went with the first phone
            self.assertEqual(status, 403, again)
            self.assertNotIn(OTHER, json.dumps(hub.TEAM))

    def test_a_second_phone_is_iphone_2(self):
        with self.team_saves({"iphone": {"label": "iPhone", "address": PHONE}}):
            status, got = self.enroll(self.new_code()[1]["code"], source=OTHER)
            self.assertEqual((status, got["device"], got["label"]), (200, "iphone-2", "iPhone 2"), got)
            self.assertEqual(hub.TEAM["owner_devices"]["iphone-2"], {"label": "iPhone 2", "address": OTHER})

    def test_a_pc_enrolls_as_pc_and_its_messages_say_via_windows(self):
        """Owner API 1.149: the app sends its kind at its enrollment. A PC is "PC" where a phone is "iPhone", its
        message says via=Windows, and a device that names no kind stays an iPhone, as every phone of before the kind."""
        text = lambda receipt: hub.q1("SELECT text FROM events WHERE id=?", (receipt["event_id"],))["text"]
        with self.team_saves({}):
            status, got = self.call("/ui/owner/enroll", {"code": self.new_code()[1]["code"], "kind": "windows"},
                                    source=PHONE)
            self.assertEqual((status, got["device"], got["label"]), (200, "pc", "PC"), got)
            self.assertEqual(hub.TEAM["owner_devices"], {"pc": {"label": "PC", "address": PHONE}})
            pc = got["key"]
            status, second = self.call("/ui/owner/enroll", {"code": self.new_code()[1]["code"], "kind": "windows"},
                                       source=OTHER)
            self.assertEqual((status, second["device"], second["label"]), (200, "pc-2", "PC 2"), second)
            status, said = self.call("/ui/messages", self.command(text="A goal from the PC"), source=PHONE, token=pc)
            self.assertEqual((status, text(said)), (200, "[owner via Windows] A goal from the PC"), said)
            hub.TEAM["addresses"]["dev-host"] = "127.0.0.9"
            hub.TEAM["agents"]["dev-lead"] = {"role": "worker", "runtime": "claude", "machine": "dev-host", "can": []}
            body = self.command(recipient="dev-lead", text="Look at the build")
            status, worker = self.call("/ui/messages", body, source=PHONE, token=pc)
            self.assertEqual(text(worker), f"[owner chat request_id={body['request_id']} via=Windows] Look at the build")
            rows = {d["device"]: d for d in self.call("/ui/owner/devices")[1]["devices"]}
            self.assertEqual((rows["pc"]["kind"], rows["pc-2"]["kind"]), ("windows", "windows"))
        # A phone that names no kind: "iPhone", via=iPhone, and the kind iphone in the Mac's list.
        hub.TEAM["owner_devices"] = {"iphone": {"label": "iPhone", "address": OTHER}}
        self.code()
        self.assertIsNone(self.call("/ui/owner/devices")[1]["devices"][0]["kind"], "no key, no kind")
        phone = self.enrolled(source=OTHER)
        status, said = self.call("/ui/messages", self.command(text="A goal from the phone"), source=OTHER, token=phone)
        self.assertEqual((status, text(said)), (200, "[owner via iPhone] A goal from the phone"), said)
        self.assertEqual(self.call("/ui/owner/devices")[1]["devices"][0]["kind"], "iphone")
        # A key of before the kind (its row has none) is an iPhone's.
        hub.q("UPDATE owner_devices SET kind=NULL WHERE device='iphone'")
        self.assertEqual((hub.owner_device_class("iphone"), hub.owner_device_class(None)), ("iPhone", None))
        self.assertEqual(self.call("/ui/owner/devices")[1]["devices"][0]["kind"], "iphone")
        # The same device takes a new key as a PC: the kind is the newest enrollment's.
        status, made = self.code()
        status, got = self.call("/ui/owner/enroll", {"code": made["code"], "kind": "windows"}, source=OTHER)
        self.assertEqual((status, got["label"], hub.owner_device_class("iphone")), (200, "iPhone", "Windows"), got)
        # A database of before the kind gets the column from migrate, and its keys are iPhones'.
        hub.q("ALTER TABLE owner_devices DROP COLUMN kind")
        self.assertEqual(hub.migrate(), [])
        self.assertEqual(hub.owner_device_class("iphone"), "iPhone")

    def test_an_unknown_kind_is_refused_and_burns_no_code(self):
        with self.team_saves({}):
            made = self.new_code()[1]
            for kind in ("android", "", 1, "Windows", ["windows"], {"kind": "windows"}):
                with self.subTest(kind=kind):
                    status, body = self.call("/ui/owner/enroll", {"code": made["code"], "kind": kind}, source=PHONE)
                    self.assertEqual((status, body["error"]), (400, "kind is iphone or windows"), body)
            self.assertEqual(hub.TEAM["owner_devices"], {})
            status, got = self.call("/ui/owner/enroll", {"code": made["code"], "kind": "iphone"}, source=PHONE)
            self.assertEqual((status, got["device"], got["label"]), (200, "iphone", "iPhone"), got)

    def test_no_machine_of_the_fleet_becomes_a_device_and_the_code_stays_open(self):
        with self.team_saves({}):
            made = self.new_code()[1]
            status, body = self.enroll(made["code"], source="127.0.0.2")    # the hub's own machine
            self.assertEqual(status, 400, body)
            self.assertIn("address of a machine", body["error"])
            self.assertEqual(hub.TEAM["owner_devices"], {})
            self.assertEqual(self.enroll(made["code"])[0], 200)             # the phone still can

    def test_five_wrong_codes_stop_an_unknown_address_for_an_hour(self):
        with self.team_saves({}):
            self.new_code()
            for _ in range(5):
                self.assertEqual(self.enroll("AAAA-BBBB", source=OTHER)[0], 403)
            status, body = self.enroll("AAAA-BBBB", source=OTHER)
            self.assertEqual(status, 429, body)
            self.assertEqual(hub.TEAM["owner_devices"], {})

    def test_the_hub_keeps_no_new_code_and_a_new_one_replaces_it(self):
        with self.team_saves({}):
            first = self.new_code()[1]["code"]
            second = self.new_code()[1]["code"]
            self.assertEqual(self.enroll(first)[0], 403)                    # one open code for a new phone
            self.assertNotIn(second, json.dumps([dict(r) for r in hub.q("SELECT * FROM ui_controls")]))
            self.assertEqual(self.enroll(second)[0], 200)

    def test_only_the_mac_makes_a_code_for_a_new_phone_and_at_most_four_devices(self):
        key = self.enrolled()
        status, body = self.new_code(source=PHONE, token=key)
        self.assertEqual((status, body["auth"]), (403, "device_not_allowed"))
        hub.TEAM["owner_devices"].update({f"tab-{n}": {"label": f"Tab {n}", "address": f"127.0.0.{20 + n}"}
                                          for n in range(3)})
        status, body = self.new_code()
        self.assertEqual(status, 409, body)

    # ---- the compact read
    def test_the_mobile_read_gives_heads_and_stays_small(self):
        for n in range(30):
            self.task(title=f"Task {n}", state="completed" if n else "working")
        hub.touch("manager")
        need = self.need()
        answered = self.need()
        hub.q("UPDATE needs SET answer='yes', answered=? WHERE id=?", (hub.now(), answered))
        status, state = self.call("/ui/mobile")
        self.assertEqual(status, 200)
        self.assertEqual(set(state), {"schema_version", "db", "time", "manager_flag", "manager_warning", "agents",
                                      "needs", "answered_needs", "tasks", "recent", "holds", "outcomes", "chat_apps",
                                      "counts", "ui_features", "token"})
        self.assertEqual([n["id"] for n in state["needs"]], [need])     # the open item only
        self.assertEqual([(n["id"], n["answer"]) for n in state["answered_needs"]], [(answered, "yes")])
        # a head carries what the Mac's state word reads, so the phone's Tasks row can say "Stalled" as its page does
        self.assertLessEqual({"stalled_since", "nudge_level", "missing_since"}, set(state["tasks"][0]))
        self.assertEqual([t["state"] for t in state["tasks"]], ["working"])
        self.assertEqual(len(state["recent"]), 20)                      # the last twenty that ended
        self.assertNotIn("details", state["tasks"][0])                  # a head has no text of its own
        self.assertEqual(state["counts"], {"tasks_open": 1, "needs_open": 1, "messages": 0, "reports": 0})
        self.assertEqual([a["name"] for a in state["agents"]], ["manager"])
        self.assertEqual(state["agents"][0]["open_tasks"], 1)
        self.assertEqual(state["agents"][0]["machine"], "hub")          # its server, for its page (Runs on)
        whole = self.call("/ui/state")[1]
        self.assertLess(len(json.dumps(state)), len(json.dumps(whole)) // 4)

    def test_an_unchanged_fleet_answers_304(self):
        status, headers, body = self.raw("/ui/mobile")
        self.assertEqual(status, 200)
        tag = headers["ETag"]
        again = self.raw("/ui/mobile", headers={"If-None-Match": tag})
        self.assertEqual((again[0], again[2]), (304, b""))
        self.assertEqual(again[1]["ETag"], tag)
        self.task()                                                     # one change, and the tag is another one
        status, headers, body = self.raw("/ui/mobile", headers={"If-None-Match": tag})
        self.assertEqual(status, 200)
        self.assertNotEqual(headers["ETag"], tag)
        self.assertTrue(json.loads(body)["tasks"])

    def test_check_ins_keep_the_tag_and_a_helper_that_goes_quiet_changes_it(self):
        """live_changes: the tag hashes whether each helper was seen in the last minute, not when, so a check-in is
        no new tag and an idle fleet answers 304. The change token rides in the answer and is no new tag either."""
        hub.touch("manager")
        status, headers, body = self.raw("/ui/mobile")
        tag = headers["ETag"]
        self.assertEqual(json.loads(body)["token"], hub.change_token())
        hub.touch("manager")                                            # a check-in: a new last_seen
        with hub.area("quiet"):                                         # and a new time of its window list
            hub.q("UPDATE agents SET alive_ts=? WHERE name='manager'", (hub.now(),))
        hub.log("hub", "a line of the hub's own log")                   # activity: a new token
        self.assertEqual(self.raw("/ui/mobile", headers={"If-None-Match": tag})[0], 304)
        with hub.area("quiet"):                                         # time passes: the helper is quiet a minute
            hub.q("UPDATE agents SET last_seen=? WHERE name='manager'", (hub.now() - hub.MOBILE_SEEN - 1,))
        status, headers, _ = self.raw("/ui/mobile", headers={"If-None-Match": tag})
        self.assertEqual(status, 200)
        self.assertNotEqual(headers["ETag"], tag)

    def test_a_tasks_activity_is_a_new_tag(self):
        """The Tasks list says how long ago each task did something, so the tag keeps `last_activity`. It moves only
        while a task works: an idle fleet still answers 304."""
        task = self.task()
        tag = self.raw("/ui/mobile")[1]["ETag"]
        self.assertEqual(self.raw("/ui/mobile", headers={"If-None-Match": tag})[0], 304)
        time.sleep(0.01)
        hub.activity(task, "Bash")
        self.assertEqual(self.raw("/ui/mobile", headers={"If-None-Match": tag})[0], 200)

    def test_a_device_waits_for_a_change_and_its_own_requests_wake_nothing(self):
        key = self.enrolled()
        status, body = self.call("/ui/mobile", source=PHONE, token=key)
        self.assertEqual(status, 200)
        before = hub.CHANGE["state"]
        for _ in range(3):                                              # each request writes the device's own times
            self.call("/ui/mobile", source=PHONE, token=key)
            status, waited = self.call(f"/ui/wait?db=test-generation&since={body['token']}&wait=0",
                                       source=PHONE, token=key)
            self.assertEqual(status, 200, waited)
            self.assertEqual(waited["token"].split(".")[:2], body["token"].split(".")[:2])
        self.assertEqual(hub.CHANGE["state"], before)                   # so a phone never wakes itself
        status, refused = self.call("/ui/wait?db=test-generation&wait=0", source=PHONE)
        self.assertEqual((status, refused["auth"]), (403, "device_key_required"))

    def test_the_reads_refuse_another_generation(self):
        for path in ("/ui/mobile", "/ui/mobile/chat/manager", "/ui/mobile/task/1"):
            with self.subTest(path=path):
                self.assertEqual(self.call(path + "?db=other")[0], 409)

    # ---- one conversation, one task
    def test_the_phone_reads_the_fifty_newest_answered_items_oldest_first(self):
        """D-7 item 2: an answered request card folds to two lines in its chat, so the phone needs the items that
        were answered as well as the open ones: the fifty newest, oldest first."""
        ids = [self.need() for _ in range(55)]
        hub.q("UPDATE needs SET answer='done', answered=? WHERE id<>?", (hub.now(), ids[-1]))   # the last stays open
        state = self.call("/ui/mobile")[1]
        self.assertEqual([n["id"] for n in state["needs"]], [ids[-1]])
        self.assertEqual([n["id"] for n in state["answered_needs"]], ids[4:-1])         # 50 of the 54 answered
        self.assertEqual(len(state["answered_needs"]), hub.MOBILE_ANSWERED)

    def test_an_answer_in_a_chat_names_the_item_it_answers(self):
        """The Mac's chat links an owner's answer to its request card by the message's kind and need; the phone's
        chat page says the same as `answer_to`, and an ordinary message has none."""
        need = self.need()
        self.message(text="An ordinary message")
        hub.ins("INSERT INTO ui_requests(request_id,kind,need_id,text,event_id,created,client,recipient) "
                "VALUES(?,'answer',?,'yes',?,?,'deterministic-test','manager')",
                (str(uuid.uuid4()), need, hub.emit("manager", "say", "[owner] yes"), hub.now() + 1))
        items = self.call("/ui/mobile/chat/manager")[1]["items"]
        self.assertEqual([(i["kind"], i["text"], i["answer_to"]) for i in items],
                         [("message", "An ordinary message", None), ("message", "yes", need)])

    def test_a_chat_page_holds_the_messages_and_the_reports_in_time_order(self):
        self.message(text="First")
        time.sleep(0.01)
        self.report(text="Answer")
        self.message(agent="manager", text="Second")
        status, page = self.call("/ui/mobile/chat/manager")
        self.assertEqual(status, 200)
        self.assertEqual([(i["kind"], i["text"]) for i in page["items"]],
                         [("message", "First"), ("report", "Answer"), ("message", "Second")])
        self.assertEqual(page["cursor"], page["items"][-1]["ts"])
        after = self.call(f"/ui/mobile/chat/manager?since={page['cursor']}")[1]
        self.assertEqual(after["items"], [])                            # the cursor gives what comes after it
        self.assertEqual(self.call("/ui/mobile/chat/nobody")[0], 404)

    def test_the_compact_read_names_the_features_as_the_whole_snapshot_does(self):
        state, mobile = self.call("/ui/state")[1], self.call("/ui/mobile")[1]
        self.assertEqual(mobile["ui_features"], state["ui_features"])    # the phone reads /ui/state for nothing
        self.assertIn("mobile", mobile["ui_features"])

    def test_a_chat_page_says_which_report_the_agent_wrote_first(self):
        self.report(text="An answer")
        hub.ins("INSERT INTO owner_reports(text,about,created,agent,pushed) VALUES(?,'',?,'manager',1)",
                ("The build is broken.", hub.now()))
        items = self.call("/ui/mobile/chat/manager")[1]["items"]
        self.assertEqual([(i["text"], i["pushed"]) for i in items],
                         [("An answer", False), ("The build is broken.", True)])

    def test_a_chat_page_holds_at_most_thirty_items_and_the_newest(self):
        for n in range(35):
            self.report(text=f"Report {n}")
        items = self.call("/ui/mobile/chat/manager")[1]["items"]
        self.assertEqual(len(items), 30)
        self.assertEqual(items[-1]["text"], "Report 34")

    def test_a_task_page_holds_the_task_its_notes_and_its_holds(self):
        task = self.task()
        first = hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (task, "manager", hub.now(), "Started"))
        status, page = self.call(f"/ui/mobile/task/{task}")
        self.assertEqual(status, 200)
        self.assertEqual(page["task"]["id"], task)
        self.assertEqual(page["task"]["details"], "d" * 2000)           # the details come with the task itself
        self.assertEqual([n["text"] for n in page["notes"]], ["Started"])
        self.assertEqual(page["cursor"], first)
        hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (task, "manager", hub.now(), "Ready"))
        after = self.call(f"/ui/mobile/task/{task}?since={first}")[1]
        self.assertEqual([n["text"] for n in after["notes"]], ["Ready"])
        self.assertEqual(self.call("/ui/mobile/task/9999")[0], 404)

    def test_a_task_page_holds_the_permissions_that_the_mac_thread_shows(self):
        """Owner API 1.161: the task's permission that waits and its refusal, with the six fields of the Mac's row; an
        allowed one and another task's are not in it, and nothing that GET /ui/state does not give a device already."""
        task, other = self.task(), self.task(title="Other")
        t0 = hub.now()
        rows = [(task, "Bash", '{"command":"curl -s https://help.example.com"}', None, None),
                (task, "Write", '{"file_path":"replies/1.json"}', "deny", "not that folder"),
                (task, "Read", '{"file_path":"notes.md"}', "allow", "fine"),
                (other, "Bash", '{"command":"ls"}', None, None)]
        for n, (on, tool, given, decision, reason) in enumerate(rows):
            hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created,decision,reason) VALUES(?,?,?,?,?,?,?,?)",
                    (on, "manager", tool, given, f"key-{n}", t0 + n, decision, reason))
        page = self.call(f"/ui/mobile/task/{task}")[1]
        self.assertEqual([p["tool"] for p in page["permissions"]], ["Bash", "Write"])
        self.assertEqual(set(page["permissions"][0]), {"id", "tool", "input", "created", "decision", "reason"})
        self.assertEqual((page["permissions"][1]["decision"], page["permissions"][1]["reason"]), ("deny", "not that folder"))
        self.assertIn('"curl -s https://help.example.com"', page["permissions"][0]["input"])
        state = {p["id"]: p for p in self.call("/ui/state")[1]["permissions"]}
        for p in page["permissions"]:
            self.assertTrue(set(p.items()) <= set(state[p["id"]].items()), "the state gives a device the same and more")

    def test_a_task_page_holds_its_guidance_as_the_state_does(self):
        """Owner API 1.162: the task's guidance, with the fields and values of GET /ui/state's steers; another task's is
        not in it."""
        task, other = self.task(), self.task(title="Other")
        for on, text in ((task, "Look at the logs first."), (other, "Not this one."), (task, "Then the config.")):
            status, body = self.call(f"/ui/tasks/{on}/steer", {"request_id": str(uuid.uuid4()), "db": hub.kv_get("db_id"),
                                                              "expected_attempt": 1, "text": text})
            self.assertEqual(status, 200, body)
        page = self.call(f"/ui/mobile/task/{task}")[1]
        self.assertEqual([s["text"] for s in page["steers"]], ["Look at the logs first.", "Then the config."])
        state = {s["id"]: s for s in self.call("/ui/state")[1]["steers"]}
        for steer in page["steers"]:
            self.assertEqual(steer, state[steer["id"]])

    def test_a_task_head_names_its_parent_as_the_state_does(self):
        """Owner API 1.162: each head carries parent, the value of GET /ui/state, so a device can see that a task waits
        for its open subtasks."""
        lead = self.task(title="Lead")
        child = self.task(title="Child")
        hub.q("UPDATE tasks SET parent=? WHERE id=?", (lead, child))
        heads = {t["id"]: t for t in self.call("/ui/mobile")[1]["tasks"]}
        state = {t["id"]: t for t in self.call("/ui/state")[1]["tasks"]}
        self.assertEqual((heads[child]["parent"], heads[lead]["parent"]), (lead, None))
        self.assertEqual(heads[child]["parent"], state[child]["parent"])

    def test_a_task_page_holds_its_subtasks_and_its_parent(self):
        """Owner API 1.163: the heads of its subtasks by id, an ended one too, and the head of its parent; a task with
        neither has an empty list and null."""
        lead, first, second, alone = (self.task(title=t) for t in ("Lead", "First", "Second", "Alone"))
        hub.q("UPDATE tasks SET parent=? WHERE id IN (?,?)", (lead, first, second))
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (first,))
        page = self.call(f"/ui/mobile/task/{lead}")[1]
        self.assertEqual([(t["id"], t["state"]) for t in page["subtasks"]], [(first, "completed"), (second, "working")])
        self.assertEqual(set(page["subtasks"][0]), set(hub.MOBILE_HEAD))
        self.assertIsNone(page["parent_task"])
        child = self.call(f"/ui/mobile/task/{second}")[1]
        self.assertEqual((child["parent_task"]["id"], child["parent_task"]["title"]), (lead, "Lead"))
        self.assertEqual(self.call(f"/ui/mobile/task/{alone}")[1]["subtasks"], [])

    def test_a_parked_task_head_says_until_when_as_the_state_does(self):
        """Owner API 1.161: an open task that its agent parked until a time has parked_until in the device's heads, the
        same value as GET /ui/state, which a device may read already; a task that is not parked has no such key."""
        parked, free = self.task(title="Parked"), self.task(title="Free")
        due = hub.now() + 3600
        with hub.LOCK:
            hub.DB.execute("UPDATE tasks SET live_path=? WHERE id=?", (hub.PARKED_PATH + "16:00", parked))
            hub.commit()
        hub.ins("INSERT INTO reminders(due,note,done,agent,task,created) VALUES(?,?,0,?,?,?)",
                (due, "come back", "manager", parked, hub.now()))
        heads = {t["id"]: t for t in self.call("/ui/mobile")[1]["tasks"]}
        self.assertEqual(heads[parked]["parked_until"], due)
        self.assertNotIn("parked_until", heads[free])
        state = {t["id"]: t for t in self.call("/ui/state")[1]["tasks"]}
        self.assertEqual(state[parked]["parked_until"], heads[parked]["parked_until"])

    def test_a_registered_login_never_leaves_in_a_mobile_read(self):
        password, salt = "SyntheticPassword123", "synthetic-salt"
        hub.ins("INSERT INTO secrets(salt,hash,len) VALUES(?,?,?)",
                (salt, hashlib.sha256((salt + password).encode()).hexdigest(), len(password)))
        self.report(text=f"the password is {password}")
        page = self.call("/ui/mobile/chat/manager")[1]
        self.assertNotIn(password, json.dumps(page))
        self.assertIn(hub.MASK, json.dumps(page))

    def test_a_login_in_an_agents_newest_message_never_reaches_the_phone_in_part(self):
        """The phone's list shows the start of each agent's newest message (MOBILE_PREVIEW characters). Until
        11 November 2026 the hub cut it before scrub, and scrub finds no login in a part of one: a login that was
        registered after its message was stored, and that lay across the cut, reached the phone in part. Now a message
        that holds a login is the mask, wherever the login is in it, and a message with none is cut as before."""
        hub.TEAM["addresses"]["w1"] = "127.0.0.3"
        for name in ("leo", "mia"):
            hub.TEAM["agents"][name] = {"role": "worker", "runtime": "claude", "machine": "w1", "can": []}
        password, salt, cut = "Across-The-Cut-4242-Login", "cut-salt", hub.MOBILE_PREVIEW
        across = "w " * ((cut - 10) // 2) + password + " and the rest of it"
        self.assertLess(across.index(password), cut)
        self.assertGreater(across.index(password) + len(password), cut)
        clean = "a plain report " * 20
        self.report(agent="manager", text=across)
        self.report(agent="leo", text="x " * cut + password)         # the login after the cut
        self.report(agent="mia", text=clean)
        hub.ins("INSERT INTO secrets(salt,hash,len) VALUES(?,?,?)",  # registered after the messages were stored
                (salt, hashlib.sha256((salt + password).encode()).hexdigest(), len(password)))
        state = self.call("/ui/mobile")[1]
        self.assertEqual({a["name"]: a["last"]["preview"] for a in state["agents"]},
                         {"manager": hub.MASK, "leo": hub.MASK, "mia": clean[:cut]})
        self.assertNotIn(password[:6], json.dumps(state))

    def test_the_phones_list_knows_since_when_a_chat_waits_for_its_answer(self):
        """Owner feature chat_waits (UI-API.md 1.142): agents[].waits_since is the time of the owner's newest chat
        message to an agent that waits for its answer, by the apps' rule for "Thinking". The phone's list of chats had
        only each conversation's last line, so it could say "Thinking" only for a chat that the phone itself had read."""
        hub.TEAM["addresses"]["w1"] = "127.0.0.3"
        hub.TEAM["agents"]["leo"] = {"role": "worker", "runtime": "claude", "machine": "w1", "can": []}

        def waits():
            state = self.call("/ui/mobile")[1]
            self.assertIn("chat_waits", state["ui_features"])
            return {a["name"]: a["waits_since"] for a in state["agents"]}

        def says(agent, at, kind="message"):
            rid = str(uuid.uuid4())
            hub.ins("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient) "
                    "VALUES(?,?,'Is it live?',?,?,'deterministic-test',?)",
                    (rid, kind, hub.emit(agent, "chat", "Is it live?"), at, agent))
            return rid

        def reports(agent, at, reply=None, pushed=0):
            hub.ins("INSERT INTO owner_reports(text,about,created,agent,in_reply_to,pushed) VALUES('Yes.','',?,?,?,?)",
                    (at, agent, reply, pushed))

        self.assertEqual(waits(), {"manager": None, "leo": None})          # no message yet
        first = says("leo", 100.0)
        self.assertEqual(waits(), {"manager": None, "leo": 100.0})         # his message waits
        reports("leo", 101.0, pushed=1)
        self.assertEqual(waits()["leo"], 100.0)                            # a report that the agent wrote first is no reply
        reports("leo", 102.0, reply=first)
        self.assertIsNone(waits()["leo"])                                  # a report that names it answers it
        second = says("leo", 103.0)
        self.assertEqual(waits()["leo"], 103.0)                            # a reply to an older message answers no newer one
        says("leo", 104.0, kind="answer")
        self.assertEqual(waits()["leo"], 103.0)                            # an answer to a Needs-you item is no message that waits
        reports("leo", 105.0)
        self.assertIsNone(waits()["leo"])                                  # the agent wrote since, with no name: nothing is known
        says("manager", 106.0)
        reports("manager", 105.5)
        self.assertEqual(waits(), {"manager": 106.0, "leo": None})         # what it wrote before the message says nothing
        self.assertTrue(second)


def register(secret, salt):
    hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
            (f"login {salt}", salt, hashlib.sha256((salt + secret).encode()).hexdigest(), len(secret), ""))


class MobileMoment(unittest.TestCase):
    """GET /ui/mobile from its own moment of the records, as main() opens them: in WAL mode, with read connections of
    their own (hub.wal_on, hub.readers_for, hub.state_moment). Until 11 November 2026 the whole build of the page held
    the hub's lock. It borrows the harness of OwnerAPI and the reads of Devices, and not their checks, which run once,
    above."""
    tearDown, connect, request = OwnerAPI.tearDown, OwnerAPI.connect, OwnerAPI.request
    raw = Devices.raw

    def setUp(self):
        OwnerAPI.setUp(self)
        clock = patch.object(hub, "now", return_value=T0)
        clock.start()
        self.addCleanup(clock.stop)
        self.assertEqual(hub.wal_on(), (True, None))
        hub.readers_for(self.path)
        self.addCleanup(hub.readers_for, None)

    def read(self, headers=None):
        """One GET /ui/mobile from the owner's Mac: (its status, its ETag, its body)."""
        status, got, body = self.raw("/ui/mobile", headers=headers)
        return status, got.get("ETag"), body

    def statements(self, fn):
        """fn(), and each statement that the hub's connection and its read connections ran meanwhile, in their order:
        (the statement, whether its thread held the hub's lock). As test_state_read.OwnMoment.statements."""
        seen, real_reader, real_back = [], hub.reader, hub.reader_back

        def trace(sql):
            seen.append((sql, hub.LOCK._is_owned()))

        def reader():
            got = real_reader()
            if got is not None:
                got[0].set_trace_callback(trace)
            return got

        def reader_back(conn, turn):
            conn.set_trace_callback(None)
            real_back(conn, turn)
        hub.DB.set_trace_callback(trace)
        try:
            with patch.object(hub, "reader", reader), patch.object(hub, "reader_back", reader_back):
                return fn(), seen
        finally:
            hub.DB.set_trace_callback(None)

    def fill(self):
        """Rows in each part of the phone's page, and a registered login inside a text of each part that shows one: the
        title of an open task, the why of an open item, the discussion of another, the answer of an answered one, the
        note of a hold, the title of an outcome and an agent's newest report (its chat preview). 23 tasks that ended,
        of which the page has the newest 20, and 3 open ones. The manager seen a moment ago, with a turn end and a
        limit that ended; a lead seen more than a minute ago, with an open limit and six usage windows, of which the
        page has four; an inactive worker with no row."""
        register(LOGIN, "s1")
        hidden = f"the key is {LOGIN} now"
        hub.TEAM["addresses"]["w1"] = "127.0.0.3"
        hub.TEAM["agents"].update({
            "leo": {"role": "lead", "runtime": "codex", "machine": "w1", "can": ["shell"], "title": "Developer",
                    "reports_to": "manager"},
            "ivy": {"role": "worker", "runtime": "claude", "machine": "w1", "can": [], "active": False,
                    "reports_to": "leo"}})
        with hub.LOCK:
            x = lambda sql, args=(): hub.DB.execute(sql, args).lastrowid
            for n in range(1, 27):
                state = ("completed", "failed", "canceled", "rejected")[n % 4] if n < 24 else \
                    ("working", "input-required")[n % 2]
                x("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,started,last_activity,"
                  "attempt,follows,stalled_since) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (hidden if n == 25 else f"Task {n}", f"details of task {n}", "a test passes", "[]",
                   ("leo", "manager")[n % 2], "manager", state, T0 - 900 * (27 - n), T0 - 800 * (27 - n),
                   T0 - 60 * (27 - n), 1, n - 1 if n % 5 == 0 else None, T0 - 300 if n == 26 else None))
            for n in range(1, 6):                       # three open items, then two answered ones
                answered = n > 3
                need = x("INSERT INTO needs(title,why,todo,raised,by,answer,answered,answered_by,options,chosen,kind,"
                         "secret,details,multi,chose) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (f"Item {n}", hidden if n == 1 else "the owner decides", "say yes", T0 - 600 + n, "manager",
                          (hidden if n == 5 else "Yes") if answered else None, T0 - 100 + n if answered else None,
                          "owner" if answered else None, json.dumps(["Yes", "No"]) if n % 2 else None,
                          0 if n == 5 else None, "secret" if n == 3 else None,
                          json.dumps({"kind": "api_key", "env": "SHOP_API_KEY"}) if n == 3 else None,
                          "the long part" if n == 2 else None, 1 if n == 2 else 0,
                          json.dumps([0, 1]) if n == 2 else None))
                x("INSERT INTO need_talk(need,ts,who,text,request_id) VALUES(?,?,?,?,?)",
                  (need, T0 - 500, "owner", hidden if n == 2 else "why this one?", f"talk-{n}"))
            x("UPDATE needs SET door_call=? WHERE id=1", ("ef" * 32,))          # its view reads the fleet's id
            for name, seen in (("manager", T0 - 5), ("leo", T0 - hub.MOBILE_SEEN - 30)):
                x("INSERT OR REPLACE INTO agents(name,last_seen,alive,alive_ts,client,client_seen) VALUES(?,?,?,?,?,?)",
                  (name, seen, "owner-chat", seen, "fleet-helper", seen))
            x("INSERT INTO agent_usage(name,data) VALUES(?,?)",
              ("leo", json.dumps({"limits": {"windows": [{"label": f"window {k}", "used_percent": 10 * k,
                                                          "resets_at": T0 + 3600 * k, "note": "kept out"}
                                                         for k in range(6)]}})))
            x("INSERT INTO agent_limits(agent,since,until,reset_known,task) VALUES(?,?,?,?,?)",
              ("leo", T0 - 300, T0 + 3600, 1, 25))
            x("INSERT INTO agent_limits(agent,since,until,reset_known,task,ended) VALUES(?,?,?,?,?,?)",
              ("manager", T0 - 900, T0 - 600, 1, None, T0 - 600))
            for n, (agent, said) in enumerate((("manager", "hello"), ("manager", "are you there?"), ("leo", "a plan"))):
                event = x("INSERT INTO events(agent,kind,task,text,created,extra,read_at) VALUES(?,?,?,?,?,?,?)",
                          (agent, "say", None, said, T0 - 400 + n, "{}", T0 - 390 + n if n < 2 else None))
                x("INSERT INTO ui_requests(request_id,kind,text,event_id,created,client,recipient) "
                  "VALUES(?,?,?,?,?,?,?)", (f"req-{n}", "message", said, event, T0 - 400 + n, "mac-app", agent))
            x("INSERT INTO owner_reports(text,about,created,agent,pushed) VALUES(?,?,?,?,?)",
              (hidden, "the export", T0 - 200, "leo", 1))
            hold = x("INSERT INTO holds(task,kind,by,note,state,created,attempt) VALUES(?,?,?,?,?,?,?)",
                     (25, "limit", "leo", hidden, "held", T0 - 20, 1))
            x("INSERT INTO holds(task,kind,by,note,state,created,attempt,released,released_by) "
              "VALUES(?,?,?,?,?,?,?,?,?)",
              (24, "pause", "manager", "a pause", "released", T0 - 900, 1, T0 - 800, "owner"))
            x("INSERT INTO outcomes(task,attempt,hold,tool_call_id,title,kind,state,created) VALUES(?,?,?,?,?,?,?,?)",
              (25, 1, hold, "toolu_1", hidden, "send", "open", T0 - 20))
            x("INSERT INTO outcomes(task,attempt,hold,tool_call_id,title,kind,state,created,resolved,by) "
              "VALUES(?,?,?,?,?,?,?,?,?,?)", (24, 1, hold, "toolu_2", "a send", "send", "resolved", T0 - 900,
                                              T0 - 800, "owner"))
            for key, value in (("fleet_id", "fleet-test-1"), ("turn_ended:manager", str(T0 - 50)), ("mgr_flag", "1"),
                               ("mgr_flag_kind", "manager_down"), ("mgr_flag_since", str(T0 - 120)),
                               ("chat_apps_paused", "1")):
                x("INSERT OR REPLACE INTO kv(k,v) VALUES(?,?)", (key, value))
            hub.commit()

    def test_the_page_of_its_own_moment_is_the_same_bytes_and_statements_as_under_the_lock(self):
        """The phone's page read from its own connection is the same bytes, with the same ETag, as the page read under
        the lock, with the same statements in the same order, for a fleet with nothing yet and for one with every part.
        Of its statements only the start of its read transaction holds the lock (the moment), where the read under the
        lock holds it for the whole build; scrub's one read of the logins comes after the build. An unchanged fleet
        answers 304 from its own moment too."""
        for full in (False, True):
            with self.subTest(full=full):
                if full:
                    self.fill()
                hub.readers_for(self.path)
                own, seen = self.statements(self.read)
                hub.readers_for(None)
                locked, before = self.statements(self.read)
                self.assertEqual(own, locked)
                self.assertEqual(own[0], 200)
                start, end = seen.index(("BEGIN", True)), seen.index(("ROLLBACK", False))
                self.assertEqual(seen[start + 1], ("SELECT count(*) FROM sqlite_master", True))
                build = seen[start + 2:end]
                self.assertEqual([s for s, _ in seen[:start] + build + seen[end + 1:]], [s for s, _ in before])
                self.assertGreater(len(build), 30 if full else 10)
                self.assertEqual({held for _, held in build}, {False})
                self.assertEqual({held for _, held in before[start:start + len(build)]}, {True})
                self.assertIn(("SELECT * FROM needs WHERE answer IS NULL ORDER BY id", False), build)
                self.assertEqual(seen[end + 1:], [("SELECT salt, hash, len FROM secrets ORDER BY id", True)])
                self.assertEqual(before[start + len(build):], seen[end + 1:])
        page, text = json.loads(own[2]), own[2].decode()
        self.assertEqual(([t["id"] for t in page["tasks"]], [t["id"] for t in page["recent"]]),
                         ([24, 25, 26], list(range(4, 24))))
        self.assertEqual(([n["id"] for n in page["needs"]], [n["id"] for n in page["answered_needs"]]),
                         ([1, 2, 3], [4, 5]))
        self.assertEqual([(a["name"], len(a["usage"]), bool(a["limit"])) for a in page["agents"]],
                         [("manager", 0, False), ("leo", 4, True), ("ivy", 0, False)])
        self.assertEqual((len(page["holds"]), len(page["outcomes"]), page["chat_apps"]), (1, 1, {"paused": True}))
        self.assertEqual(page["counts"], {"tasks_open": 3, "needs_open": 3, "messages": 3, "reports": 1})
        self.assertEqual((page["time"], page["token"], page["needs"][0]["door_fleet"]),
                         (T0, hub.change_token(), "fleet-test-1"))
        self.assertEqual((text.count(hub.MASK), LOGIN in text), (7, False))
        hub.readers_for(self.path)
        again, seen = self.statements(lambda: self.read({"If-None-Match": own[1]}))
        self.assertEqual(again, (304, own[1], b""))
        self.assertIn(("BEGIN", True), seen)

    def test_a_writer_does_not_wait_for_the_page_and_is_not_in_it(self):
        """Two writers come during a read of the phone's page: the first as soon as its moment lets the lock go, and the
        second at the build's first statement, while the build waits for it. Neither waits for the read. The page is
        the one of its moment: without their rows, with the team, the token and the time of before them. The second
        writer's thread reads its own row meanwhile and has no moment: SNAP is each thread's own. A login registered
        after the moment is masked all the same, because scrub reads the logins after the build. The next read has it
        all, with another ETag, and a phone that waits with the token of the first read reads again at once."""
        self.fill()
        hub.q("UPDATE tasks SET title=? WHERE id=24", (f"the new key is {LATER}",))
        clock, seen, real_reader, real_back = {"at": T0}, {}, hub.reader, hub.reader_back
        hub.now.side_effect = lambda: clock["at"]

        def first():                            # as an owner command writes: rows, and the team that goes with them
            hub.ins("INSERT INTO needs(title,why,todo,raised,by) VALUES(?,?,?,?,?)",
                    ("Item 6", "it came during the read", "say yes", T0, "manager"))
            hub.ins("INSERT INTO tasks(title,owner,requester,state,created,needs,attempt) VALUES(?,?,?,?,?,?,?)",
                    ("Task 27", "leo", "manager", "working", T0, "[]", 1))
            register(LATER, "s3")
            with hub.LOCK:
                hub.TEAM.update(agents=dict(hub.TEAM["agents"], uma={"role": "worker", "runtime": "codex",
                                                                    "machine": "w1", "can": []}))
                hub.changed()
            clock["at"] = T0 + 7
            seen["token"] = hub.change_token()

        def second():
            seen["its moment"] = hub.SNAP.conn
            hub.ins("INSERT INTO needs(title,why,todo,raised,by) VALUES(?,?,?,?,?)",
                    ("Item 7", "it came during the build", "say yes", T0, "manager"))
            seen["its rows"] = [r["title"] for r in hub.q("SELECT title FROM needs WHERE title='Item 7'")]

        def run(writer, name):
            thread = threading.Thread(target=writer)
            thread.start()
            thread.join(PATIENCE)
            seen[name] = thread.is_alive()      # it still waits: for the lock, which the read holds

        class Landing:
            """hub.LOCK, which lets the first writer in as soon as the read's moment lets it go."""
            def __init__(self, lock):
                self.lock = lock

            def acquire(self, *args, **kwargs):
                return self.lock.acquire(*args, **kwargs)

            def release(self):
                self.lock.release()
                if seen.get("moment") == threading.get_ident() and not self.lock._is_owned():
                    seen["moment"], seen["moment's token"] = None, hub.change_token()
                    run(first, "first waited")

            __enter__ = acquire

            def __exit__(self, *exc):
                self.release()

            def _is_owned(self):
                return self.lock._is_owned()

        def trace(sql):
            if sql == "SELECT count(*) FROM sqlite_master" and "first waited" not in seen:
                seen["moment"] = threading.get_ident()
            elif sql not in ("BEGIN", "ROLLBACK") and "first waited" in seen and "second waited" not in seen:
                run(second, "second waited")

        def reader():
            got = real_reader()
            if got is not None:
                got[0].set_trace_callback(trace)
            return got

        def reader_back(conn, turn):
            conn.set_trace_callback(None)
            real_back(conn, turn)
        team = list(hub.TEAM["agents"])
        with patch.object(hub, "LOCK", Landing(hub.LOCK)), patch.object(hub, "reader", reader), \
                patch.object(hub, "reader_back", reader_back):
            status, tag, body = self.read()
        page = json.loads(body)
        self.assertEqual((status, seen["first waited"], seen["second waited"]), (200, False, False))
        self.assertEqual((seen["its moment"], seen["its rows"]), (None, ["Item 7"]))
        self.assertEqual([n["title"] for n in page["needs"]], ["Item 1", "Item 2", "Item 3"])
        self.assertEqual([t["id"] for t in page["tasks"]], [24, 25, 26])
        self.assertEqual([a["name"] for a in page["agents"]], team)
        self.assertEqual((page["time"], page["token"]), (T0, seen["moment's token"]))
        self.assertNotEqual(page["token"], seen["token"])
        self.assertEqual(page["tasks"][0]["title"], hub.MASK)
        self.assertNotIn(LATER, body.decode())
        self.assertEqual(self.request(f"/ui/wait?db=test-generation&since={page['token']}&wait=5"),
                         (200, {"db": "test-generation", "token": hub.change_token()}))
        status, newer, body = self.read({"If-None-Match": tag})
        then = json.loads(body)
        self.assertEqual(status, 200)
        self.assertNotEqual(newer, tag)
        self.assertEqual([n["title"] for n in then["needs"]], ["Item 1", "Item 2", "Item 3", "Item 6", "Item 7"])
        self.assertEqual([t["id"] for t in then["tasks"]], [24, 25, 26, 27])
        self.assertEqual([a["name"] for a in then["agents"]], team + ["uma"])
        self.assertEqual((then["token"], then["time"]), (hub.change_token(), T0 + 7))

    def test_the_build_reads_the_records_and_the_team_only_through_its_moment(self):
        """Every function that the body of the phone's `with state_moment()` reaches in hub.py reads the records through
        q, q1, read_rows or read_row and the team through team_read, which read the moment's, and none writes, as
        test_state_read holds for GET /ui/state. One that named DB or TEAM itself would read the records or the team of
        now, and a writer would write from a read. scrub is not reached: it reads the logins after the build, so that a
        login registered meanwhile is masked. The scan follows names: a call through an attribute (self.x(), obj.y()),
        a function in a table or code in another module is not followed. The block has no self. at all, and this test
        keeps it so."""
        tree = ast.parse(inspect.getsource(hub))
        functions = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                functions[node.name] = node
                for sub in node.body if isinstance(node, ast.ClassDef) else ():
                    if isinstance(sub, ast.FunctionDef):
                        functions[f"{node.name}.{sub.name}"] = sub

        def names(node):
            return {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        # The route's body is hub.phone_mobile since the connected apps call it too (the build specification of the
        # MCP address, section 4), and the route calls it after ui_allowed.
        self.assertIn("phone_mobile", names(functions["Handler.ui_mobile"]))
        block = next(n for n in ast.walk(functions["phone_mobile"]) if isinstance(n, ast.With)
                     and ast.unparse(n.items[0].context_expr) == "state_moment()")
        selfs = [ast.unparse(n) for stmt in block.body for n in ast.walk(stmt)      # the scan cannot follow these
                 if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self"]
        self.assertEqual(selfs, [])
        reached, todo = set(), [n for stmt in block.body for n in names(stmt) if n in functions]
        while todo:
            name = todo.pop()
            if name not in reached:
                reached.add(name)
                todo.extend(n for n in names(functions[name]) if n in functions)
        watched = {"DB", "TEAM", "LOCK", "ins", "kv_set", "log", "emit", "transaction", "committed", "log_row"}
        self.assertEqual({name: names(functions[name]) & watched for name in reached
                          if names(functions[name]) & watched},
                         {"q": {"DB", "LOCK"}, "read_rows": {"DB", "LOCK"}, "team_read": {"TEAM"},
                          "commit": {"DB"}, "counted": {"DB"}, "held": {"LOCK"}})
        self.assertGreater(len(reached), 25)
        self.assertTrue({"mobile_state", "mobile_agent", "need_view", "agents", "setting", "kv_get"} <= reached)
        self.assertNotIn("scrub", reached)
        writes = re.compile(r"\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER)\b", re.I)     # through q: refused
        self.assertEqual([(name, n.value) for name in sorted(reached) for n in ast.walk(functions[name])
                          if isinstance(n, ast.Constant) and isinstance(n.value, str) and writes.match(n.value)], [])


if __name__ == "__main__":
    unittest.main()

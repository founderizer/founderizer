"""Deterministic checks of the owner's attachments: the upload, the message that carries the files, the owner route
and the agent's one-time download line. No vendor call and no live fleet."""
import hashlib
import json
import os
import re
import tempfile
import unittest
import urllib.error
import urllib.request
import uuid
from unittest.mock import patch

import hub
import test_ui_api

PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(64))
JPEG = b"\xff\xd8\xff" + bytes(range(64))
PDF = b"%PDF-1.7\n" + bytes(range(64))


class Attachments(test_ui_api.OwnerAPI):
    def setUp(self):
        super().setUp()
        self.files = tempfile.TemporaryDirectory(prefix="fleet-attach-test-")
        hub.CFG["attachment_dir"] = self.files.name
        hub.TEAM["addresses"]["worker-host"] = "127.0.0.3"
        hub.TEAM["agents"]["worker"] = {"role": "worker", "runtime": "codex", "machine": "worker-host"}
        hub.TEAM["agents"]["other"] = {"role": "worker", "runtime": "codex", "machine": "worker-host"}

    def tearDown(self):
        hub.CFG.pop("attachment_dir", None)
        hub.CFG.pop("attachment_keep", None)
        hub.ATTACH_LINKS.clear()
        self.files.cleanup()
        super().tearDown()

    # ---- the helpers of these checks

    def send_bytes(self, data, mime="image/png", name="shot.png", request_id=None, client="deterministic-test",
                   db="test-generation"):
        headers = {"Content-Type": mime, "X-Fleet-Client": client, "X-Fleet-Name": name,
                   "X-Fleet-Request-Id": request_id or str(uuid.uuid4())}
        return self.call("POST", f"/ui/attachments?db={db}", data, headers)

    def call(self, method, path, data=None, headers=None):
        req = urllib.request.Request(self.base + path, data=data, headers=headers or {}, method=method)
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with op.open(req, timeout=5) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as r:
            with r:
                return r.code, r.read(), dict(r.headers)

    def answer(self, status_body):
        return json.loads(status_body)

    def upload(self, data=PNG, **changes):
        code, body, _ = self.send_bytes(data, **changes)
        self.assertEqual(code, 200, body)
        return json.loads(body)

    def message(self, attachments, recipient="worker", **changes):
        body = self.command(recipient=recipient, attachments=attachments, **changes)
        code, receipt = self.request("/ui/messages", body)
        return code, receipt, body

    def task(self, owner="worker"):
        tid = hub.ins("INSERT INTO tasks(title,owner,state,attempt,created) VALUES(?,?,?,?,?)",
                      ("Look at the mockup", owner, "working", 1, hub.now()))
        return tid, ("test-generation", f"T-{tid}", 1)

    def register_login(self, token="SPARROW-CANARY-9931", salt="canary-salt"):
        hub.ins("INSERT INTO secrets(label,salt,hash,len) VALUES(?,?,?,?)",
                ("canary", salt, hashlib.sha256((salt + token).encode()).hexdigest(), len(token)))
        return token

    # ---- the upload

    def test_one_upload_is_one_file_and_the_same_request_id_never_a_second(self):
        request_id = str(uuid.uuid4())
        first = self.upload(PNG, request_id=request_id)
        self.assertFalse(first["replayed"])
        self.assertEqual(first["sha256"], hashlib.sha256(PNG).hexdigest())
        self.assertEqual((first["size"], first["mime"], first["name"]), (len(PNG), "image/png", "shot.png"))
        kept = os.path.join(self.files.name, first["sha256"] + ".png")
        with open(kept, "rb") as f:
            self.assertEqual(f.read(), PNG)
        self.assertEqual(oct(os.stat(kept).st_mode)[-3:], "600")
        again = self.upload(PNG, request_id=request_id)
        self.assertTrue(again["replayed"])
        self.assertEqual(again["id"], first["id"])
        self.assertEqual(self.count("attachments"), 1)
        code, body, _ = self.send_bytes(JPEG, mime="image/jpeg", name="other.jpg", request_id=request_id)
        self.assertEqual(code, 409, body)
        self.assertEqual(self.count("attachments"), 1)

    def test_the_bytes_must_be_what_the_request_says_and_hold_no_login(self):
        for data, mime, status in ((PNG, "image/jpeg", 415), (b"MZ\x90", "application/zip", 415),
                                   (PNG, "application/x-sh", 415), (b"", "image/png", 400),
                                   (b"\xff\xfe\x00bad", "text/plain", 415)):
            code, body, _ = self.send_bytes(data, mime=mime, name="f")
            self.assertEqual(code, status, body)
        self.assertEqual(self.count("attachments"), 0)
        token = self.register_login()
        code, body, _ = self.send_bytes(f"the login is {token}\n".encode(), mime="text/plain", name="notes.txt")
        self.assertEqual(code, 422, body)
        self.assertEqual(self.count("attachments"), 0)
        self.upload(b"nothing secret here\n", mime="text/plain", name="notes.txt")

    def test_a_file_larger_than_the_limit_is_refused_before_it_is_kept(self):
        with patch.object(hub, "ATTACH_MAX", 1024):
            code, body, _ = self.send_bytes(PNG + bytes(2048), name="big.png")
            self.assertEqual(code, 413, body)
        self.assertEqual(self.count("attachments"), 0)
        self.assertEqual(os.listdir(self.files.name), [])

    def test_the_upload_needs_the_owner_the_generation_and_a_uuid(self):
        code, body, _ = self.send_bytes(PNG, db="another-generation")
        self.assertEqual(code, 409, body)
        code, body, _ = self.send_bytes(PNG, request_id="not-a-uuid")
        self.assertEqual(code, 400, body)
        code, body, _ = self.send_bytes(PNG, client="")
        self.assertEqual(code, 400, body)
        self.assertEqual(self.count("attachments"), 0)

    # ---- the message that carries the files

    def test_a_message_carries_its_files_and_tells_the_agent_how_to_read_them(self):
        one, two = self.upload(PNG, name="mockup.png"), self.upload(PDF, mime="application/pdf", name="spec.pdf")
        code, receipt, body = self.message([one["id"], two["id"]])
        self.assertEqual(code, 200, receipt)
        self.assertEqual(receipt["attachments"], [one["id"], two["id"]])
        event = hub.q1("SELECT * FROM events WHERE id=?", (receipt["event_id"],))
        self.assertIn(f"A-{one['id']} mockup.png (image/png", event["text"])
        self.assertIn(f"A-{two['id']} spec.pdf (application/pdf", event["text"])
        self.assertIn("read_attachment", event["text"])
        self.assertIn(body["text"], event["text"])
        for row in hub.q("SELECT * FROM attachments ORDER BY id"):
            self.assertEqual(row["message"], body["request_id"])
        _, state = self.request()
        sent = next(m for m in state["messages"] if m["request_id"] == body["request_id"])
        self.assertEqual([a["id"] for a in sent["attachments"]], [one["id"], two["id"]])
        self.assertEqual(sent["attachments"][0]["sha256"], hashlib.sha256(PNG).hexdigest())
        self.assertEqual(set(sent["attachments"][0]),
                         {"id", "name", "mime", "size", "sha256", "created", "kept"})
        self.assertIsNone(sent["attachments"][0]["kept"])       # nothing is kept until the owner says so
        self.assertIn("attachments", state["ui_features"])

    def test_a_message_without_files_says_nothing_about_them(self):
        code, receipt, body = self.message([])
        self.assertEqual(code, 200, receipt)
        self.assertEqual(receipt["attachments"], [])
        event = hub.q1("SELECT * FROM events WHERE id=?", (receipt["event_id"],))
        self.assertNotIn("read_attachment", event["text"])
        _, state = self.request()
        self.assertEqual(next(m for m in state["messages"] if m["request_id"] == body["request_id"])["attachments"], [])

    def test_the_same_request_id_is_one_event_and_the_same_files(self):
        one = self.upload(PNG, name="mockup.png")
        two = self.upload(JPEG, mime="image/jpeg", name="other.jpg")
        code, receipt, body = self.message([one["id"]])
        self.assertEqual(code, 200, receipt)
        code, again = self.request("/ui/messages", body)
        self.assertEqual(code, 200, again)
        self.assertTrue(again["replayed"])
        self.assertEqual((again["event_id"], again["attachments"]), (receipt["event_id"], [one["id"]]))
        self.assertEqual(self.count("events"), 1)
        changed = dict(body, attachments=[one["id"], two["id"]])
        code, refused = self.request("/ui/messages", changed)
        self.assertEqual(code, 409, refused)
        self.assertEqual(self.count("events"), 1)

    def test_a_file_belongs_to_one_message_and_to_the_client_that_sent_it(self):
        one = self.upload(PNG)
        self.assertEqual(self.message([one["id"]])[0], 200)
        code, refused, _ = self.message([one["id"]])
        self.assertEqual(code, 409, refused)
        code, refused, _ = self.message([one["id"] + 99])
        self.assertEqual(code, 404, refused)
        other = self.upload(JPEG, mime="image/jpeg", name="o.jpg", client="another-client/1")
        code, refused, _ = self.message([other["id"]])
        self.assertEqual(code, 409, refused)
        code, refused, _ = self.message([1, 1])
        self.assertEqual(code, 400, refused)
        code, refused, _ = self.message(list(range(1, hub.ATTACH_PER_MESSAGE + 2)))
        self.assertEqual(code, 400, refused)
        self.assertEqual(self.count("events"), 1)

    def test_an_edit_keeps_the_files_and_an_edit_that_brings_one_is_a_correction(self):
        one = self.upload(PNG)
        _, receipt, body = self.message([one["id"]])
        # edit_in_place: the words alone change the message itself, and the file it carries stays with it
        _, edited, _ = self.message([], text="Other words.", replaces_request_id=body["request_id"])
        self.assertTrue(edited["edited"])
        self.assertEqual(self.count("events"), 1)
        event = hub.q1("SELECT text FROM events WHERE id=?", (receipt["event_id"],))["text"]
        self.assertIn("Other words.", event)
        self.assertIn(f"A-{one['id']} shot.png", event)
        self.assertEqual([r["id"] for r in hub.q("SELECT id FROM attachments WHERE message=?",
                                                 (body["request_id"],))], [one["id"]])
        # a file that comes with the edit is a new message under it: an edit changes words, and brings nothing
        two = self.upload(JPEG, mime="image/jpeg", name="other.jpg")
        _, with_file, _ = self.message([two["id"]], text="And this one.", replaces_request_id=body["request_id"])
        self.assertFalse(with_file["edited"])
        self.assertEqual(self.count("events"), 2)
        self.assertIn("[Correction to request", hub.q1("SELECT text FROM events WHERE id=?",
                                                       (with_file["event_id"],))["text"])

    def test_an_answer_to_a_needs_you_item_carries_files_too(self):
        need = self.need()
        one = self.upload(PNG, name="proof.png")
        body = self.command(answer="Here is the proof.", attachments=[one["id"]])
        code, receipt = self.request(f"/ui/needs/{need}", body)
        self.assertEqual(code, 200, receipt)
        self.assertEqual(receipt["attachments"], [one["id"]])
        event = hub.q1("SELECT * FROM events WHERE id=?", (receipt["event_id"],))
        self.assertIn(f"A-{one['id']} proof.png", event["text"])
        self.assertIsNotNone(hub.q1("SELECT answered FROM needs WHERE id=?", (need,))["answered"])

    def test_a_file_may_travel_without_a_caption(self):
        one = self.upload(PNG, name="mockup.png")
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "attachments": [one["id"]],
                "recipient": "worker"}
        code, receipt = self.request("/ui/messages", body)
        self.assertEqual(code, 200, receipt)
        event = hub.q1("SELECT * FROM events WHERE id=?", (receipt["event_id"],))
        self.assertTrue(event["text"].startswith("[owner chat request_id="))
        self.assertIn("\n[The owner attached 1 file: A-", event["text"])
        self.assertNotIn("  ", event["text"])
        code, refused = self.request("/ui/messages", dict(body, request_id=str(uuid.uuid4()), attachments=[]))
        self.assertEqual(code, 400, refused)

    def test_the_phone_reads_the_files_with_its_chat_page(self):
        one = self.upload(PNG, name="mockup.png")
        code, receipt, body = self.message([one["id"]])
        self.assertEqual(code, 200, receipt)
        code, page = self.request("/ui/mobile/chat/worker?db=test-generation")
        self.assertEqual(code, 200, page)
        item = next(i for i in page["items"] if i["id"] == body["request_id"])
        self.assertEqual([a["id"] for a in item["attachments"]], [one["id"]])
        self.assertEqual(item["attachments"][0]["sha256"], hashlib.sha256(PNG).hexdigest())
        plain = next(i for i in page["items"] if i["id"] != body["request_id"] and i["kind"] == "message")\
            if any(i["kind"] == "message" and i["id"] != body["request_id"] for i in page["items"]) else None
        self.assertIsNone(plain)

    # ---- the owner's own apps

    def test_the_owner_route_gives_the_bytes_with_their_hash(self):
        one = self.upload(PNG, name="mockup.png")
        code, data, headers = self.call("GET", f"/ui/attachments/{one['id']}?db=test-generation")
        self.assertEqual(code, 200)
        self.assertEqual(data, PNG)
        self.assertEqual(headers["X-Fleet-SHA256"], one["sha256"])
        self.assertEqual(headers["Content-Type"], "image/png")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("mockup.png", headers["Content-Disposition"])
        self.assertEqual(self.call("GET", f"/ui/attachments/{one['id']}?db=other")[0], 409)
        self.assertEqual(self.call("GET", "/ui/attachments/999?db=test-generation")[0], 404)
        os.remove(os.path.join(self.files.name, one["sha256"] + ".png"))
        self.assertEqual(self.call("GET", f"/ui/attachments/{one['id']}?db=test-generation")[0], 410)

    # ---- the agent

    def line(self, agent, context, attachment_id, task):
        text, failed = hub.call_tool(agent, "read_attachment",
                                     {"task_id": f"T-{task}", "attachment_id": attachment_id}, context)
        return text, failed

    def test_the_agent_gets_one_line_that_works_one_time(self):
        one = self.upload(PNG, name="mockup.png")
        self.assertEqual(self.message([one["id"]])[0], 200)
        task, context = self.task("worker")
        text, failed = self.line("worker", context, f"A-{one['id']}", task)
        self.assertFalse(failed, text)
        self.assertIn("curl -sfo 'mockup.png'", text)
        self.assertIn("one time", text)
        token = re.search(r"/attachment/file/([A-Za-z0-9_-]+)", text).group(1)
        code, data, headers = self.call("GET", f"/attachment/file/{token}")
        self.assertEqual(code, 200)
        self.assertEqual(data, PNG)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(self.call("GET", f"/attachment/file/{token}")[0], 404)
        self.assertEqual(self.call("GET", "/attachment/file/made-up-token")[0], 404)

    def test_the_line_ends_with_its_time_and_with_its_task(self):
        one = self.upload(PNG)
        self.assertEqual(self.message([one["id"]])[0], 200)
        task, context = self.task("worker")
        text, _ = self.line("worker", context, f"A-{one['id']}", task)
        token = re.search(r"/attachment/file/([A-Za-z0-9_-]+)", text).group(1)
        hub.ATTACH_LINKS[token]["ends"] = hub.now() - 1
        self.assertEqual(self.call("GET", f"/attachment/file/{token}")[0], 404)
        text, _ = self.line("worker", context, f"A-{one['id']}", task)
        token = re.search(r"/attachment/file/([A-Za-z0-9_-]+)", text).group(1)
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (task,))
        self.assertEqual(self.call("GET", f"/attachment/file/{token}")[0], 404)

    def test_only_the_agent_that_got_the_file_may_read_it(self):
        one = self.upload(PNG)
        two = self.upload(JPEG, mime="image/jpeg", name="o.jpg")
        self.assertEqual(self.message([one["id"]], recipient="worker")[0], 200)
        task, context = self.task("worker")
        other_task, other_context = self.task("other")
        text, failed = self.line("other", other_context, f"A-{one['id']}", other_task)
        self.assertTrue(failed, text)
        self.assertIn("not a file that the owner sent to you", text)
        text, failed = self.line("worker", context, f"A-{two['id']}", task)      # sent up, never sent
        self.assertTrue(failed, text)
        text, failed = self.line("worker", context, "A-404", task)
        self.assertTrue(failed, text)
        text, failed = self.line("worker", context, "mockup.png", task)
        self.assertTrue(failed, text)
        self.assertIn("for example A-3", text)
        self.assertFalse(hub.ATTACH_LINKS)

    def test_a_file_that_left_the_hub_is_said_plainly(self):
        one = self.upload(PNG)
        self.assertEqual(self.message([one["id"]])[0], 200)
        task, context = self.task("worker")
        os.remove(os.path.join(self.files.name, one["sha256"] + ".png"))
        text, failed = self.line("worker", context, f"A-{one['id']}", task)
        self.assertTrue(failed, text)
        self.assertIn("no longer on the hub", text)

    def test_the_bytes_stay_outside_the_checkout(self):
        one = self.upload(PNG)
        kept = os.path.join(self.files.name, one["sha256"] + ".png")
        self.assertTrue(os.path.exists(kept))
        self.assertFalse(os.path.abspath(kept).startswith(os.path.dirname(os.path.abspath(hub.__file__)) + os.sep))
        hub.CFG.pop("attachment_dir")
        self.assertEqual(hub.ATTACH_DIR, os.path.expanduser("~/.fleet/attachments"))
        hub.CFG["attachment_dir"] = self.files.name

    # ---- the sweep: what the hub lets go

    def sweep(self, at=None):
        """One sweep now. On the hub's own tick ten minutes pass between two of them, which this test does not wait."""
        hub.kv_set("attachment_sweep_at", None)
        hub.attachment_sweep(hub.now() if at is None else at)

    def path_of(self, one):
        return os.path.join(self.files.name, one["sha256"] + hub.ATTACH_TYPES[one["mime"]][0])

    def age(self, seconds, one=None, message=None):
        """What the same upload would look like that many seconds ago: the row, its file and the message that carries
        it all carry the age, as they would on a hub that kept them since then."""
        then = hub.now() - seconds
        if one:
            hub.q("UPDATE attachments SET created=? WHERE id=?", (then, one["id"]))
            if os.path.exists(self.path_of(one)):
                os.utime(self.path_of(one), (then, then))
        if message:
            hub.q("UPDATE ui_requests SET created=? WHERE request_id=?", (then, message))

    def rows(self):
        return [r["id"] for r in hub.q("SELECT id FROM attachments ORDER BY id")]

    def kept(self):
        return sorted(os.listdir(self.files.name))

    def swept(self):
        return [r["what"] for r in hub.q("SELECT what FROM log WHERE what LIKE 'attachment sweep%' ORDER BY id")]

    def test_a_file_that_no_message_carries_goes_after_an_hour(self):
        one = self.upload(PNG, name="mockup.png")
        self.sweep()
        self.assertEqual((self.rows(), self.kept()), ([one["id"]], [one["sha256"] + ".png"]))
        self.age(2 * 3600, one)
        hub.attachment_sweep(hub.now())                     # the tick holds the next sweep back for ten minutes
        self.assertEqual(self.rows(), [one["id"]])
        self.sweep()
        self.assertEqual((self.rows(), self.kept()), ([], []))
        self.assertEqual(self.swept(), ["attachment sweep: 1 rows gone, 1 files removed (0 no row named)"])
        self.assertNotIn(one["sha256"], self.swept()[0])     # counts only: never a name and never a hash
        self.assertNotIn("mockup.png", self.swept()[0])

    def test_a_file_that_a_message_carries_waits_for_the_retention(self):
        one = self.upload(PNG, name="mockup.png")
        code, receipt, body = self.message([one["id"]])
        self.assertEqual(code, 200, receipt)
        self.age(2 * 3600, one)                             # the hour is for a file that no message carries
        self.sweep()
        self.assertEqual((self.rows(), self.swept()), ([one["id"]], []))
        self.age(91 * 24 * 3600, one, body["request_id"])
        self.sweep()
        self.assertEqual((self.rows(), self.kept()), ([], []))
        self.assertEqual(self.swept(), ["attachment sweep: 1 rows gone, 1 files removed (0 no row named)"])

    def test_the_retention_is_a_setting_with_ninety_days_as_its_default(self):
        self.assertEqual(hub.attachment_keep(), 90 * 24 * 3600)
        one = self.upload(PNG)
        code, receipt, body = self.message([one["id"]])
        self.assertEqual(code, 200, receipt)
        self.age(2 * 24 * 3600, one, body["request_id"])
        self.sweep()
        self.assertEqual(self.rows(), [one["id"]])
        hub.CFG["attachment_keep"] = 24 * 3600
        self.sweep()
        self.assertEqual((self.rows(), self.kept()), ([], []))

    def test_two_rows_of_the_same_bytes_are_one_file_that_the_last_row_takes(self):
        one, two = self.upload(PNG, name="mockup.png"), self.upload(PNG, name="again.png")
        self.assertNotEqual(one["id"], two["id"])
        self.assertEqual((one["sha256"], self.kept()), (two["sha256"], [one["sha256"] + ".png"]))
        code, receipt, body = self.message([two["id"]])
        self.assertEqual(code, 200, receipt)
        self.age(2 * 3600, one)                             # the row goes, the bytes stay: the other row names them
        self.sweep()
        self.assertEqual((self.rows(), self.kept()), ([two["id"]], [one["sha256"] + ".png"]))
        self.assertEqual(self.swept(), ["attachment sweep: 1 rows gone, 0 files removed (0 no row named)"])
        self.assertIsNotNone(hub.attachment_bytes(hub.q1("SELECT * FROM attachments WHERE id=?", (two["id"],))))
        self.age(91 * 24 * 3600, two, body["request_id"])
        self.sweep()
        self.assertEqual((self.rows(), self.kept()), ([], []))

    def test_a_file_that_no_row_names_goes_after_the_same_hour(self):
        one = self.upload(PNG, name="mockup.png")
        strays = [os.path.join(self.files.name, "0" * 64 + ".png"),
                  os.path.join(self.files.name, "1" * 64 + ".png.7.part")]
        for name in strays:
            with open(name, "wb") as f:
                f.write(PNG)
        self.sweep()
        self.assertEqual(len(self.kept()), 3)               # of this hour: an upload may still be writing them
        for name in strays:
            os.utime(name, (hub.now() - 2 * 3600, hub.now() - 2 * 3600))
        self.sweep()
        self.assertEqual((self.rows(), self.kept()), ([one["id"]], [one["sha256"] + ".png"]))
        self.assertEqual(self.swept(), ["attachment sweep: 0 rows gone, 2 files removed (2 no row named)"])

    def test_nothing_that_a_recent_message_carries_is_touched(self):
        one = self.upload(PNG, name="mockup.png")
        two = self.upload(PDF, mime="application/pdf", name="spec.pdf")
        code, receipt, _ = self.message([one["id"], two["id"]])
        self.assertEqual(code, 200, receipt)
        self.sweep()
        self.assertEqual(self.rows(), [one["id"], two["id"]])
        self.assertEqual(self.kept(), sorted([one["sha256"] + ".png", two["sha256"] + ".pdf"]))
        self.assertEqual(self.swept(), [])
        task, context = self.task("worker")
        text, failed = self.line("worker", context, f"A-{one['id']}", task)
        self.assertFalse(failed, text)

    def test_the_same_bytes_again_mark_the_file_as_of_this_hour(self):
        one = self.upload(PNG, name="mockup.png")
        then = hub.now() - 2 * 3600
        os.utime(self.path_of(one), (then, then))
        self.upload(PNG, name="again.png")                  # the bytes are there: only their time moves
        self.assertGreater(os.stat(self.path_of(one)).st_mtime, then)


if __name__ == "__main__":
    unittest.main()

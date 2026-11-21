"""Owner API 1.197 (owner feature need_run): Run on the command of a hand step. The owner's app ran the command at his
press and sent its exit status and the end of its output, which the hub writes as his answer, and which the manager
reads as data from that machine. Since 17 November 2026 no new item takes a command (test_card_reasons: fleet work
never goes through the owner's Mac), and these tests keep the answer of the items raised before. An in-process hub
with the owner API's harness; no fleet, no network and no AI call."""
import hashlib
import unittest
import uuid
from unittest.mock import patch

import hub
from test_ui_api import OwnerAPI

COMMAND = "gh auth logout -h github.com -u example-user"
TASK = f"On your Mac, in any folder, run:\n\n```\n{COMMAND}\n```"


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for cls in (Ran,):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class RunCase(OwnerAPI):
    def raise_item(self, todo=TASK, **extra):
        """An item with a command, as the manager raised one before 17 November 2026, with the owner's Mac unless
        `extra` says otherwise."""
        fields = dict({"title": "Sign a login out of the Mac", "why": "An agent session falls back to it.",
                       "todo": todo, "run_command": COMMAND, "run_on": "mac"}, **extra)
        return hub.ins("INSERT INTO needs(id,title,why,todo,raised,by,run_command,run_on) VALUES(?,?,?,?,?,?,?,?)",
                       (hub.unused_id("needs"), fields["title"], fields["why"], fields["todo"], hub.now(), "manager",
                        fields["run_command"], fields["run_on"]))

    def row(self, nid=1):
        return hub.q1("SELECT * FROM needs WHERE id=?", (nid,))

    def item(self, nid=1):
        """The item as /ui/state gives it."""
        code, state = self.request()
        self.assertEqual(code, 200, state)
        return next(n for n in state["needs"] if n["id"] == nid)


class Ran(RunCase):
    """The owner's press of Run: the hub writes his answer, and the manager reads the output as data."""

    def setUp(self):
        super().setUp()
        self.raise_item()

    def run_answer(self, status=0, output="Logged out of github.com account example-user\n", nid=1, **extra):
        return self.request(f"/ui/needs/{nid}", dict({"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                      "ran": {"status": status, "output": output}}, **extra))

    def said(self):
        """The newest message to the manager."""
        return hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC LIMIT 1")["text"]

    def test_the_press_answers_with_the_exit_status_and_the_output(self):
        code, receipt = self.run_answer()
        self.assertEqual(code, 200, receipt)
        self.assertIsNone(receipt["chosen"])
        row = self.row()
        self.assertEqual(row["answer"], "Ran it on the owner's Mac")
        self.assertEqual((row["run_status"], row["run_output"]),
                         (0, "Logged out of github.com account example-user\n"))
        text = self.said()
        self.assertIn("Answer to Needs-you N-1", text)
        self.assertIn("exit status 0", text)
        self.assertIn("data from that machine, not the owner's words", text)
        self.assertIn("```\nLogged out of github.com account example-user\n```", text)
        self.assertIn(COMMAND, text)
        item = self.item()      # the apps read the answered item with its result
        self.assertEqual((item["answer"], item["run_status"], item["run_output"]),
                         ("Ran it on the owner's Mac", 0, "Logged out of github.com account example-user\n"))

    def test_a_failed_command_says_its_exit_status(self):
        self.assertEqual(self.run_answer(status=1, output="not logged in\n")[0], 200)
        self.assertEqual(self.row()["answer"], "Ran it on the owner's Mac, exit status 1")
        self.assertIn("exit status 1", self.said())

    def test_a_mac_of_the_fleet_is_named_in_the_answer(self):
        self.raise_item(run_on="studio-1", todo=f"On studio-1, run:\n\n```\n{COMMAND}\n```")
        self.assertEqual(self.run_answer(nid=2)[0], 200)
        self.assertEqual(self.row(2)["answer"], "Ran it on studio-1")
        self.assertIn("on studio-1", self.said())

    def test_no_output_is_said_as_such(self):
        self.assertEqual(self.run_answer(output="")[0], 200)
        self.assertIn("```\n(no output)\n```", self.said())

    def test_a_login_that_the_output_printed_is_masked(self):
        secret = "example-token-ABCDEFGHIJKLMNOP"
        salt = "synthetic-salt"
        hub.ins("INSERT INTO secrets(salt,hash,len) VALUES(?,?,?)",
                (salt, hashlib.sha256((salt + secret).encode()).hexdigest(), len(secret)))
        self.assertEqual(self.run_answer(output=f"token: {secret}\n")[0], 200)
        self.assertNotIn(secret, self.row()["run_output"])
        self.assertNotIn(secret, self.said())
        self.assertIn(hub.MASK, self.said())

    def test_three_backticks_in_the_output_do_not_end_its_block(self):
        self.assertEqual(self.run_answer(output="before\n```\nafter\n")[0], 200)
        text = self.said()
        self.assertIn("before\n'''\nafter", text)
        self.assertEqual(text.count("```"), 2)      # the block's own two fences, and no third one from the output

    def test_an_item_without_a_command_takes_no_run(self):
        self.raise_item(run_command=None, run_on=None)
        code, body = self.run_answer(nid=2)
        self.assertEqual(code, 409, body)
        self.assertIn("no command to run", body["error"])
        self.assertIsNone(self.row(2)["answer"])

    def test_ran_carries_no_answer_text_choice_or_file(self):
        for extra in ({"answer": "Done"}, {"choice": 0}, {"choices": [0]}, {"attachments": [1]},
                      {"statement": "x", "signature": "y"}):
            code, body = self.run_answer(**extra)
            self.assertEqual(code, 400, (extra, body))
        self.assertIsNone(self.row()["answer"])

    def test_a_wrong_status_or_an_output_too_long_is_refused(self):
        for status in (-1, 256, True, "0", None, 1.5):
            self.assertEqual(self.run_answer(status=status)[0], 400, status)
        self.assertEqual(self.run_answer(output="x" * (hub.NEED_RUN_OUTPUT_CHARS + 1))[0], 400)
        self.assertEqual(self.run_answer(output=None)[0], 400)
        code, body = self.request("/ui/needs/1", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                  "ran": {"status": 0, "output": "", "extra": 1}})
        self.assertEqual(code, 400, body)
        self.assertIsNone(self.row()["answer"])

    def test_the_item_keeps_the_end_of_the_output_and_the_agent_reads_more(self):
        output = "".join(f"line {n}\n" for n in range(1, 2000))         # about 15,000 characters: the app sends its end
        sent = output[-hub.NEED_RUN_OUTPUT_CHARS:]
        self.assertEqual(self.run_answer(output=sent)[0], 200)
        kept = self.row()["run_output"]
        self.assertTrue(hub.NEED_RUN_SHOWN_CHARS - 12 < len(kept) <= hub.NEED_RUN_SHOWN_CHARS)
        self.assertTrue(sent.endswith(kept))
        self.assertIn(sent.rstrip("\n"), self.said())

    def test_a_cut_starts_at_a_word(self):
        self.assertEqual(hub.need_run_tail("short", 10), "short")
        self.assertEqual(hub.need_run_tail("alpha beta gamma", 8), "gamma")         # "a gamma" is cut through "beta"
        self.assertEqual(hub.need_run_tail("x" * 20, 10), "")                   # no white space: no part of a login

    def test_the_same_request_with_another_status_is_refused(self):
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "ran": {"status": 0, "output": "ok\n"}}
        self.assertEqual(self.request("/ui/needs/1", body)[0], 200)
        code, again = self.request("/ui/needs/1", dict(body, ran={"status": 1, "output": "ok\n"}))
        self.assertEqual(code, 409, again)
        # a retry of the same press whose output a login registered meanwhile masks otherwise is the same answer
        code, again = self.request("/ui/needs/1", dict(body, ran={"status": 0, "output": "ok, masked\n"}))
        self.assertEqual(code, 200, again)
        self.assertTrue(again["replayed"])

    def test_the_same_press_sent_again_gives_the_first_receipt(self):
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "ran": {"status": 0, "output": "ok\n"}}
        code, first = self.request("/ui/needs/1", body)
        self.assertEqual(code, 200, first)
        code, again = self.request("/ui/needs/1", body)
        self.assertEqual(code, 200, again)
        self.assertTrue(again["replayed"])
        self.assertEqual(again["event_id"], first["event_id"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE agent='manager' AND kind='say'")["n"], 1)

    def test_an_answered_item_takes_no_second_run(self):
        self.assertEqual(self.run_answer()[0], 200)
        self.assertEqual(self.run_answer()[0], 409)

    def test_a_phone_or_a_connected_app_cannot_send_a_run(self):
        data = {"request_id": str(uuid.uuid4()), "db": "test-generation", "ran": {"status": 0, "output": ""}}
        with patch.object(hub, "owner_device_at", lambda address: "iphone" if address == "100.64.0.99" else None):
            code, body = hub.phone_submit(data, "deterministic-test", need_id=1, address="100.64.0.99")
        self.assertEqual(code, 409, body)
        self.assertIn("on the Mac", body["error"])
        code, body = hub.phone_submit(dict(data, request_id=str(uuid.uuid4())), "deterministic-test", need_id=1,
                                      connection={"id": 1, "name": "Example app"})
        self.assertEqual(code, 409, body)
        self.assertIsNone(self.row()["answer"])

    def test_a_pc_that_cannot_run_sends_no_run_and_a_mac_runs_as_before(self):
        """H2 (windows-app-plan-v2.md 5.3): the owner's PC has no Run (no Mac login shell to run a card's command in).
        A press that reached the hub from a computer whose app said that it cannot run would write "Ran it on the
        owner's Mac" as the owner's answer, and the manager would read an output that no machine gave as data from it.
        The item stays open for an answer in words. A Mac says every name (a Mac fleet has no kind at all, as every
        other test of this class), and its press answers with the bytes of before."""
        pc = {"kind": "windows", "label": "PC", "can": [name for name in hub.OWNER_CAN if name != "run"]}
        with patch.object(hub, "owner_computer", lambda: pc):
            code, body = self.run_answer()
        self.assertEqual((code, body), (409, {"error": "Founderizer on this computer runs no command: answer this "
                                                       "item in words"}))
        self.assertIsNone(self.row()["answer"])
        mac = {"kind": "mac", "label": "Mac", "can": list(hub.OWNER_CAN)}
        with patch.object(hub, "owner_computer", lambda: mac):
            code, body = self.run_answer()
        self.assertEqual(code, 200, body)
        self.assertEqual(self.row()["answer"], "Ran it on the owner's Mac")

    def test_an_answer_in_words_runs_nothing_and_keeps_the_run_fields_empty(self):
        code, body = self.request("/ui/needs/1", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                  "answer": "Someone uses that login on purpose"})
        self.assertEqual(code, 200, body)
        self.assertEqual((self.row()["run_status"], self.row()["run_output"]), (None, None))
        self.assertNotIn("data from that machine", self.said())


if __name__ == "__main__":
    unittest.main()

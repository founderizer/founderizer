"""Owner API 1.197 (owner feature need_run): Run on the command of a hand step. The manager names the one command of
the step and the Mac that it runs on; the owner's app runs it at his press and sends its exit status and the end of
its output, which the hub writes as his answer, and which the manager reads as data from that machine. An in-process
hub with the owner API's harness; no fleet, no network and no AI call."""
import hashlib
import json
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
    for cls in (Raise, Place, Ran):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class RunCase(OwnerAPI):
    def raise_item(self, todo=TASK, **extra):
        """The manager's tool, as the manager calls it, with the command and the owner's Mac unless `extra` says
        otherwise."""
        fields = dict({"title": "Sign a login out of the Mac", "why": "An agent session falls back to it.",
                       "what_to_do": todo, "run_command": COMMAND, "run_on": "mac"}, **extra)
        return hub.t_raise_needs_you("manager", {k: v for k, v in fields.items() if v is not None})

    def refused(self, **extra):
        """The sentence of the refusal, and no item raised by this call."""
        before = self.count("needs")
        with self.assertRaises(hub.ToolError) as caught:
            self.raise_item(**extra)
        self.assertEqual(self.count("needs"), before)
        return str(caught.exception)

    def row(self, nid=1):
        return hub.q1("SELECT * FROM needs WHERE id=?", (nid,))

    def item(self, nid=1):
        """The item as /ui/state gives it."""
        code, state = self.request()
        self.assertEqual(code, 200, state)
        return next(n for n in state["needs"] if n["id"] == nid)

    def mac(self, machine, system="macOS 27.2", user="owner-example"):
        """A machine of the fleet with one agent on it, its newest reading and the team's SSH user for it."""
        agent = "agent-" + machine
        hub.TEAM["agents"][agent] = {"role": "worker", "runtime": "claude", "machine": machine, "can": []}
        hub.TEAM.setdefault("addresses", {})[machine] = "100.64.0." + str(len(hub.TEAM["addresses"]) + 10)
        if user:
            hub.TEAM.setdefault("access", {})[machine] = {"ssh_user": user, "ssh_port": 22}
        hub.q("INSERT OR REPLACE INTO machine_status(agent,data,reported) VALUES(?,?,?)",
              (agent, json.dumps({"os": {"name": system, "kernel": "1"}}), hub.now()))


class Raise(RunCase):
    """What the manager may write, and what the hub refuses rather than letting the app show a Run that it should not."""

    def test_a_step_with_its_command_and_the_owners_mac_is_raised(self):
        said = self.raise_item()
        self.assertIn("Run", said)
        self.assertIn("their own Mac", said)
        self.assertEqual((self.row()["run_command"], self.row()["run_on"]), (COMMAND, "mac"))
        item = self.item()
        self.assertEqual((item["run_command"], item["run_on"]), (COMMAND, "mac"))
        self.assertIsNone(item["run_status"])
        self.assertIsNone(item["run_output"])
        self.assertIn("need_run", hub.ui_features())

    def test_an_item_without_a_command_is_the_item_of_before(self):
        self.raise_item(run_command=None, run_on=None)
        self.assertIsNone(self.row()["run_command"])
        self.assertIsNone(self.item()["run_on"])

    def test_the_command_and_its_place_go_together(self):
        self.assertIn("go together", self.refused(run_on=None))
        self.assertIn("go together", self.refused(run_command=None))

    def test_the_task_shows_the_command_as_a_code_block_of_its_own(self):
        self.assertIn("code block of its own", self.refused(todo=f"Run `{COMMAND}` on the Mac."))
        self.assertIn("code block of its own", self.refused(todo=f"Run:\n\n```\n{COMMAND} --force\n```"))
        # a block indented in a numbered step is the same block for the apps (MessageBlock.parse)
        self.raise_item(todo=f"1. Open Terminal.\n2. Run:\n   ```bash\n   {COMMAND}\n   ```")
        self.assertEqual(self.row()["run_command"], COMMAND)

    def test_the_command_is_one_line_of_printable_ascii(self):
        two = COMMAND + "\necho done"
        self.assertIn("one line", self.refused(run_command=two, todo=f"```\n{two}\n```"))
        for odd in ("gh auth status​", "gh\tauth status", "gh auth status — now"):
            self.assertIn("not plain text", self.refused(run_command=odd, todo=f"```\n{odd}\n```"))
        self.assertIn("no space before or after", self.refused(run_command=" " + COMMAND))
        long = "echo " + "a" * hub.NEED_RUN_CHARS
        self.assertIn("at most", self.refused(run_command=long, todo=f"```\n{long}\n```"))

    def test_a_wide_gap_of_spaces_is_refused(self):
        hidden = "gh auth status" + " " * (hub.NEED_RUN_GAP + 1) + "; echo more"
        self.assertIn("run of more than", self.refused(run_command=hidden, todo=f"```\n{hidden}\n```"))
        shown = "gh auth status" + " " * hub.NEED_RUN_GAP + "; echo more"
        self.raise_item(run_command=shown, todo=f"```\n{shown}\n```")

    def test_a_command_that_asks_for_a_password_gets_no_run(self):
        for command in ("sudo rm -rf /opt/example", "cd /tmp && sudo -v", "echo $(sudo id)", "x;sudo y",
                        "echo then sudo"):
            self.assertIn("sudo", self.refused(run_command=command, todo=f"```\n{command}\n```"))
        # a word that only holds the letters is no sudo
        self.raise_item(run_command="visudo-check --help", todo="```\nvisudo-check --help\n```")

    def test_a_card_of_another_route_takes_no_command(self):
        said = self.refused(add_device=True, options=["Show the picture", "Not now"])
        self.assertIn("own routes", said)

    def test_a_question_of_an_agent_takes_no_command(self):
        # the agent that asked would get only the words of the answer, and the output comes to the manager
        said = self.refused(question_id="Q-1")
        self.assertIn("takes no question_id", said)


class Place(RunCase):
    """Where Run may run: the owner's own Mac, or a Mac of the fleet that his Mac reaches over SSH."""

    def task_on(self, machine):
        return f"On {machine}, in any folder, run:\n\n```\n{COMMAND}\n```"

    def test_a_mac_of_the_fleet_that_the_owners_mac_reaches(self):
        self.mac("studio-1")
        said = self.raise_item(run_on="studio-1", todo=self.task_on("studio-1"))
        self.assertIn("on studio-1", said)
        self.assertEqual(self.row()["run_on"], "studio-1")

    def test_the_words_name_the_place_that_run_runs_on(self):
        self.mac("studio-1")
        self.mac("studio-2")
        # a Mac of the fleet: its name stands in the words
        self.assertIn("by that machine's name", self.refused(run_on="studio-1"))
        # the words name another Mac of the fleet than the one Run runs on
        self.assertIn("name one place", self.refused(run_on="studio-1", todo=self.task_on("studio-1") + "\nThen studio-2."))
        self.assertIn("name one place", self.refused(todo=self.task_on("studio-2")))
        # a command may name a machine, and a server's name may stand in the words
        self.mac("web-1", system="Ubuntu 24.04.1 LTS", user="root")
        named = "ssh studio-2 uptime"
        self.raise_item(run_command=named, todo=f"On your Mac, for web-1, run:\n\n```\n{named}\n```")
        self.assertEqual(self.row()["run_command"], named)
        # a Mac of the fleet's card does not say "your Mac"; a name in inline code is words that he reads
        self.assertIn("by that machine's name", self.refused(
            run_on="studio-1", todo=f"On studio-1 (not your Mac), run:\n\n```\n{COMMAND}\n```"))
        self.raise_item(run_on="studio-1", todo=f"On `studio-1`, run:\n\n```\n{COMMAND}\n```")
        self.assertEqual(self.row(2)["run_on"], "studio-1")
        # "this Mac Studio" names a kind of Mac, not the owner's own
        self.raise_item(run_on="studio-1", todo=f"On studio-1, this Mac Studio, run:\n\n```\n{COMMAND}\n```")
        self.assertEqual(self.row(3)["run_on"], "studio-1")

    def test_a_name_matches_as_a_word_and_not_inside_a_path_or_a_longer_name(self):
        self.mac("studio")
        for words in ("Close Visual Studio Code first.", "Your files are in ~/dev/studio/app.",
                      "The backup is on studio.example.net.", "See studio-old for the old one."):
            self.raise_item(todo=f"On your Mac, run:\n\n```\n{COMMAND}\n```\n\n{words}")
        self.assertEqual(self.count("needs"), 4)
        self.assertIn("name one place", self.refused(todo=f"On your Mac, run:\n\n```\n{COMMAND}\n```\n\nNot on studio."))

    def test_a_mac_without_an_ssh_way_that_the_app_takes(self):
        self.mac("studio-1")
        for change in ({"ssh_user": "-oProxyCommand=x"}, {"ssh_port": 0}, {"ssh_port": "22"}):
            hub.TEAM["access"]["studio-1"] = dict({"ssh_user": "owner-example", "ssh_port": 22}, **change)
            self.assertIn("no SSH way", self.refused(run_on="studio-1", todo=self.task_on("studio-1")), change)
        hub.TEAM["access"]["studio-1"] = {"ssh_user": "owner-example", "ssh_port": 22}
        hub.TEAM["addresses"]["studio-1"] = "studio-1.example.ts.net"
        self.assertIn("no SSH way", self.refused(run_on="studio-1", todo=self.task_on("studio-1")))

    def test_a_linux_server_goes_through_the_door(self):
        self.mac("web-1", system="Ubuntu 24.04.1 LTS", user="root")
        self.assertIn("door", self.refused(run_on="web-1", todo=self.task_on("web-1")))

    def test_a_machine_with_no_reading_is_no_mac(self):
        self.mac("new-1")
        hub.q("DELETE FROM machine_status")
        self.assertIn("not a Mac", self.refused(run_on="new-1", todo=self.task_on("new-1")))

    def test_a_machine_that_the_team_gives_no_ssh_user(self):
        self.mac("studio-2", user=None)
        self.assertIn("no SSH way", self.refused(run_on="studio-2", todo=self.task_on("studio-2")))

    def test_a_name_that_is_no_machine_of_the_fleet(self):
        self.mac("studio-1")
        said = self.refused(run_on="laptop-9")
        self.assertIn("studio-1", said)
        self.assertIn("laptop-9 is none of them", said)


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
        self.mac("studio-1")
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

    def test_an_answer_in_words_runs_nothing_and_keeps_the_run_fields_empty(self):
        code, body = self.request("/ui/needs/1", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                  "answer": "Someone uses that login on purpose"})
        self.assertEqual(code, 200, body)
        self.assertEqual((self.row()["run_status"], self.row()["run_output"]), (None, None))
        self.assertNotIn("data from that machine", self.said())


if __name__ == "__main__":
    unittest.main()

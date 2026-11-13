"""Owner API 1.18: the options of a Needs-you item. The agent writes the options with the question, the owner
presses one, and its own words become the item's answer on the path every answer already takes. An in-process hub
with the owner API's harness; no fleet, no network and no AI call."""
import hashlib
import json
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

import hub
from test_ui_api import OwnerAPI

OWNER = "127.0.0.1"             # the owner's Mac, as OwnerAPI sets it


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """The board answers a write with 303 back to the page; the checks read that code, not the page."""
    def redirect_request(self, *_args):
        return None


def load_tests(loader, _tests, _pattern):
    """Only this file's checks: the harness comes from OwnerAPI, its own tests stay in its own file."""
    suite = unittest.TestSuite()
    for cls in (Options, Choice, Board, Talk):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class NeedsCase(OwnerAPI):
    def raise_item(self, **extra):
        """The manager's tool, as the manager calls it."""
        return hub.t_raise_needs_you("manager", dict({"title": "Which name?", "why": "The owner names it",
                                                      "what_to_do": "Press one"}, **extra))

    def row(self, nid=1):
        return hub.q1("SELECT * FROM needs WHERE id=?", (nid,))

    def item(self, nid=1):
        """The item as /ui/state gives it."""
        code, state = self.request()
        self.assertEqual(code, 200, state)
        return next(n for n in state["needs"] if n["id"] == nid)

    def dispatched(self):
        """What left the hub for the agent: the receipt and the say event. The notify of raise_needs_you does not
        count, because it goes to the owner and is not an answer."""
        return (self.count("ui_requests"),
                hub.q1("SELECT COUNT(*) n FROM events WHERE agent='manager' AND kind='say'")["n"])

    def register(self, text):
        salt = "synthetic-salt"
        hub.ins("INSERT INTO secrets(salt,hash,len) VALUES(?,?,?)",
                (salt, hashlib.sha256((salt + text).encode()).hexdigest(), len(text)))


class Options(NeedsCase):
    """What the agent may write, and what the hub refuses rather than letting the app cut it."""

    def test_an_item_without_options_is_the_item_of_before(self):
        answer = self.raise_item()
        self.assertIn("N-1", answer)
        self.assertNotIn("presses one", answer)
        self.assertIsNone(self.row()["options"])
        self.assertIsNone(self.row()["chosen"])
        self.assertEqual(self.item()["options"], [])
        self.assertIsNone(self.item()["chosen"])

    def test_the_options_are_kept_in_the_agents_own_words_and_order(self):
        answer = self.raise_item(options=["  Tide  ", "Harbour", "Neither"])
        self.assertEqual(json.loads(self.row()["options"]), ["Tide", "Harbour", "Neither"])
        self.assertEqual(self.item()["options"], ["Tide", "Harbour", "Neither"])
        self.assertIn("Tide, Harbour, Neither", answer)

    def test_markup_is_stored_as_text_and_never_as_markup(self):
        self.raise_item(options=["<b>Tide</b>", "**Harbour**"])
        self.assertEqual(self.item()["options"], ["<b>Tide</b>", "**Harbour**"])

    def test_none_and_the_empty_list_both_mean_no_options(self):
        self.raise_item(options=None)
        self.raise_item(options=[])
        self.assertIsNone(self.row(1)["options"])
        self.assertIsNone(self.row(2)["options"])

    def refusal(self, options):
        """The sentence that says what is wrong, and no item raised by this call."""
        before = self.count("needs")
        with self.assertRaises(hub.ToolError) as caught:
            self.raise_item(options=options)
        self.assertEqual(self.count("needs"), before)
        return str(caught.exception)

    def test_one_option_is_not_a_choice(self):
        self.assertIn("2 to 6", self.refusal(["Tide"]))

    def test_a_list_too_long_to_read_as_rows_is_refused_not_cut(self):
        self.raise_item(options=["A", "B", "C", "D", "E", "F"])
        self.assertEqual(len(json.loads(self.row()["options"])), 6)
        self.assertIn("2 to 6", self.refusal(["A", "B", "C", "D", "E", "F", "G"]))

    def test_an_empty_option_is_refused(self):
        self.assertIn("empty", self.refusal(["Tide", "   "]))

    def test_an_option_that_does_not_fit_a_row_is_refused_not_cut(self):
        self.assertIn("120", self.refusal(["Tide", "x" * 121]))
        self.raise_item(options=["Tide", "x" * 120])
        self.assertEqual(len(json.loads(self.row()["options"])[1]), 120)

    def test_an_option_can_be_a_short_sentence(self):
        sentence = "Move the analytics export to vps and tell Studio to stop its own run first."
        self.raise_item(options=[sentence, "Wait for mini to answer"])
        self.assertEqual(self.item()["options"][0], sentence)

    def test_an_option_is_one_line(self):
        self.assertIn("one line", self.refusal(["Tide", "Har\nbour"]))
        self.assertIn("one line", self.refusal(["Tide", "Har\tbour"]))

    def test_two_options_cannot_say_the_same_thing(self):
        self.assertIn("same thing", self.refusal(["Tide", "TIDE"]))

    def test_options_must_be_a_list_of_texts(self):
        self.assertIn("list of short texts", self.refusal("Tide, Harbour"))
        self.assertIn("list of short texts", self.refusal(["Tide", 2]))
        self.assertIn("list of short texts", self.refusal({"a": "Tide"}))

    def test_an_option_that_holds_a_login_raises_nothing(self):
        self.register("SyntheticPassword123")
        with self.assertRaises(hub.ToolError) as caught:
            self.raise_item(options=["Tide", "SyntheticPassword123"])
        self.assertIn("login", str(caught.exception))
        self.assertEqual(self.count("needs"), 0)
        self.assertEqual(hub.leak_scan(), [])


class Choice(NeedsCase):
    """The owner's press, on the route that answers every Needs-you item."""

    def setUp(self):
        super().setUp()
        self.raise_item(options=["Tide", "Harbour", "Neither"])

    def press(self, choice, nid=1, **extra):
        return self.request(f"/ui/needs/{nid}",
                            dict({"request_id": str(uuid.uuid4()), "db": "test-generation", "choice": choice}, **extra))

    def test_the_press_becomes_the_answer_in_the_agents_own_words(self):
        code, receipt = self.press(1)
        self.assertEqual(code, 200, receipt)
        self.assertEqual(receipt["chosen"], 1)
        self.assertFalse(receipt["replayed"])
        self.assertEqual(self.row()["answer"], "Harbour")
        self.assertEqual(self.row()["chosen"], 1)
        self.assertEqual(hub.q1("SELECT text FROM ui_requests WHERE request_id=?",
                                (receipt["request_id"],))["text"], "Harbour")

    def test_the_agent_reads_the_answer_on_the_path_of_every_answer(self):
        self.press(0)
        inbox = hub.t_read_messages("manager", {})
        self.assertIn("[owner] Answer to Needs-you N-1 (Which name?): Tide", inbox)

    def test_the_owner_can_write_an_answer_that_is_none_of_them(self):
        code, receipt = self.request("/ui/needs/1", self.command(answer="Call it Anchor"))
        self.assertEqual(code, 200, receipt)
        self.assertIsNone(receipt["chosen"])
        self.assertEqual(self.row()["answer"], "Call it Anchor")
        self.assertIsNone(self.row()["chosen"])
        self.assertIn("Call it Anchor", hub.t_read_messages("manager", {}))

    def test_a_typed_answer_that_matches_an_option_is_still_typed(self):
        self.request("/ui/needs/1", self.command(answer="Tide"))
        self.assertEqual(self.row()["answer"], "Tide")
        self.assertIsNone(self.row()["chosen"])

    def test_the_same_press_sent_again_gives_the_first_receipt(self):
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "choice": 2}
        code, first = self.request("/ui/needs/1", body)
        self.assertEqual(code, 200, first)
        code, again = self.request("/ui/needs/1", body)
        self.assertEqual(code, 200, again)
        self.assertTrue(again["replayed"])
        self.assertEqual((again["event_id"], again["chosen"]), (first["event_id"], 2))
        self.assertEqual(self.dispatched(), (1, 1))

    def test_the_same_id_with_another_press_or_with_text_is_refused(self):
        body = {"request_id": str(uuid.uuid4()), "db": "test-generation", "choice": 0}
        self.assertEqual(self.request("/ui/needs/1", body)[0], 200)
        self.assertEqual(self.request("/ui/needs/1", dict(body, choice=1))[0], 409)
        self.assertEqual(self.request("/ui/needs/1", {"request_id": body["request_id"], "db": "test-generation",
                                                      "answer": "Call it Anchor"})[0], 409)
        self.assertEqual(self.row()["answer"], "Tide")
        self.assertEqual(self.row()["chosen"], 0)

    def test_an_answered_item_takes_no_second_press(self):
        self.assertEqual(self.press(0)[0], 200)
        self.assertEqual(self.press(1)[0], 409)
        self.assertEqual(self.row()["answer"], "Tide")
        self.assertEqual(self.row()["chosen"], 0)

    def test_a_press_past_the_last_option_is_refused(self):
        code, body = self.press(3)
        self.assertEqual(code, 400, body)
        self.assertIn("0 to 2", body["error"])
        self.assertIsNone(self.row()["answer"])
        self.assertEqual(self.dispatched(), (0, 0))

    def test_a_press_that_is_not_an_index_is_refused(self):
        for bad in ("1", 1.5, True, -1, [1]):
            with self.subTest(choice=bad):
                self.assertEqual(self.press(bad)[0], 400)
        self.assertEqual(self.dispatched(), (0, 0))

    def test_a_press_cannot_carry_its_own_text(self):
        code, body = self.press(0, answer="Something else")
        self.assertEqual(code, 400, body)
        self.assertIn("words of the option", body["error"])
        self.assertEqual(self.dispatched(), (0, 0))

    def test_an_item_without_options_takes_no_press(self):
        self.raise_item()
        code, body = self.press(0, nid=2)
        self.assertEqual(code, 400, body)
        self.assertIn("no options", body["error"])
        self.assertEqual(self.dispatched(), (0, 0))

    def test_a_message_to_an_agent_takes_no_press(self):
        code, body = self.request("/ui/messages", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                   "text": "A goal", "choice": 0})
        self.assertEqual(code, 400, body)
        self.assertIn("Needs-you", body["error"])
        self.assertEqual(self.dispatched(), (0, 0))

    def test_a_login_registered_after_the_item_stops_the_press(self):
        self.raise_item(options=["Tide", "Harbourside"])        # a login is never shorter than eight characters
        self.register("Harbourside")
        code, body = self.press(1, nid=2)
        self.assertEqual(code, 422, body)
        self.assertEqual(self.dispatched(), (0, 0))
        self.assertIsNone(self.row(2)["answer"])
        self.assertEqual(hub.leak_scan(), [])

    def test_an_unanswered_item_carries_its_options_to_both_reads(self):
        self.assertEqual(self.item()["options"], ["Tide", "Harbour", "Neither"])
        phone = hub.mobile_state("test-generation")["needs"]
        self.assertEqual([n["options"] for n in phone], [["Tide", "Harbour", "Neither"]])
        self.assertEqual([n["chosen"] for n in phone], [None])

    def test_a_question_of_a_conversation_offers_no_options(self):
        nid = hub.ins("INSERT INTO needs(title,why,todo,raised,by,kind,conversation) VALUES(?,?,?,?,?,?,?)",
                      ("Studio asks you", "Can you call Ana?", "goes back to Ana", hub.now(), "manager",
                       "question", 1))
        self.assertEqual(self.item(nid)["options"], [])
        self.assertEqual(self.press(0, nid=nid)[0], 400)


class Board(NeedsCase):
    """The hub's own page: the same options, one row each, so the fallback owner path needs no app."""

    def form(self, path, fields):
        """One press or one written answer on the board, without following its redirect back to the page."""
        req = urllib.request.Request(self.base + path, data=urllib.parse.urlencode(fields).encode(),
                                     headers={"Content-Type": "application/x-www-form-urlencoded",
                                              "X-Test-Source": OWNER})
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
        try:
            with op.open(req, timeout=5) as response:
                return response.status
        except urllib.error.HTTPError as response:
            with response:
                return response.code

    def page(self):
        req = urllib.request.Request(self.base + "/board", headers={"X-Test-Source": OWNER})
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with op.open(req, timeout=5) as response:
            return response.read().decode()

    def test_the_board_draws_one_row_for_each_option(self):
        self.raise_item(options=["Tide", "Harbour"])
        page = self.page()
        self.assertIn("<div><button name='choice' value='0'>Tide</button></div>", page)
        self.assertIn("<div><button name='choice' value='1'>Harbour</button></div>", page)
        self.assertIn("name='answer'", page)                # the owner can still write his own

    def test_a_press_on_the_board_answers_the_item(self):
        self.raise_item(options=["Tide", "Harbour"])
        self.assertEqual(self.form("/needs/1", {"choice": "1"}), 303)
        self.assertEqual(self.row()["answer"], "Harbour")
        self.assertEqual(self.row()["chosen"], 1)
        self.assertIn("Harbour", hub.t_read_messages("manager", {}))

    def test_the_board_still_takes_a_written_answer(self):
        self.raise_item(options=["Tide", "Harbour"])
        self.assertEqual(self.form("/needs/1", {"answer": "Call it Anchor"}), 303)
        self.assertEqual(self.row()["answer"], "Call it Anchor")
        self.assertIsNone(self.row()["chosen"])

    def test_the_board_refuses_a_press_that_names_no_option(self):
        self.raise_item(options=["Tide", "Harbour"])
        self.assertEqual(self.form("/needs/1", {"choice": "7"}), 303)
        self.assertIsNone(self.row()["answer"])

    def test_an_item_without_options_draws_no_button(self):
        self.raise_item()
        page = self.page()
        self.assertNotIn("name='choice'", page)
        self.assertIn("name='answer'", page)


if __name__ == "__main__":
    unittest.main()


class Talk(NeedsCase):
    """Owner feature need_talk (the owner, 9 November 2026): a short card with its long part behind Details and no code,
    and options that combine. Its Discuss left the apps on 13 November 2026: his own words are his one reply."""

    def test_a_card_is_short_and_its_long_part_goes_behind_details(self):
        with self.assertRaisesRegex(hub.ToolError, "The title is at most 70 characters"):
            self.raise_item(title="x" * 71)
        with self.assertRaisesRegex(hub.ToolError, "why is at most 240 characters.*Put the reasoning"):
            self.raise_item(why="y " * 121)
        self.raise_item(why="Two short sentences. He decides now.", details="The reasoning, and the facts, at length.")
        item = self.item()
        self.assertEqual((item["why"], item["details"], item["multi"], item["talk"]),
                         ("Two short sentences. He decides now.", "The reasoning, and the facts, at length.", False, []))

    def test_a_code_is_refused_anywhere_he_reads_it(self):
        for field, value in (("title", "Close T-61"), ("why", "R-3 needs it"), ("details", "as Q-59 says"),
                             ("options", ["Yes to N-4", "No"]), ("what_to_do", "Answer AM-12")):
            with self.subTest(field=field), self.assertRaisesRegex(hub.ToolError, "in plain words"):
                self.raise_item(**{field: value})
        self.raise_item(title="Move the shop off .NET 8 by 7 Dec", why="Mia needs write on 8 repositories.")    # no code

    def test_options_that_combine_are_ticked_and_their_words_joined_are_the_answer(self):
        with self.assertRaisesRegex(hub.ToolError, "multi needs options"):
            self.raise_item(multi=True)
        self.raise_item(options=["Mia moves them", "Keep the pool", "Retire the copies"], multi=True)
        self.assertTrue(self.item()["multi"])
        code, receipt = self.request("/ui/needs/1", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                     "choices": [2, 0]})
        self.assertEqual(code, 200, receipt)
        row = self.row()
        self.assertEqual((row["answer"], json.loads(row["chose"]), row["chosen"]),
                         ("Mia moves them; Retire the copies", [0, 2], None))
        self.assertIn("[owner] Answer to Needs-you N-1 (Which name?): Mia moves them; Retire the copies",
                      hub.t_read_messages("manager", {}))
        self.assertEqual(self.item()["chose"], [0, 2])

    def test_a_wrong_tick_is_refused(self):
        self.raise_item(options=["A", "B"], multi=True)
        self.raise_item(options=["C", "D"])
        for nid, body, words in ((1, {"choices": []}, "each once"), (1, {"choices": [0, 0]}, "each once"),
                                 (1, {"choices": [5]}, "choices are 0 to 1"), (1, {"choices": [True]}, "each once"),
                                 (1, {"choices": [0], "choice": 0}, "with no choice"),
                                 (2, {"choices": [0]}, "takes one choice")):
            with self.subTest(body=body):
                code, answer = self.request(f"/ui/needs/{nid}", dict({"request_id": str(uuid.uuid4()),
                                                                      "db": "test-generation"}, **body))
                self.assertEqual(code, 400, answer)
                self.assertIn(words, answer["error"])
        self.assertIsNone(self.row(1)["answer"])

    def test_one_press_on_options_that_combine_is_that_one_option(self):
        self.raise_item(options=["A", "B"], multi=True)
        code, receipt = self.request("/ui/needs/1", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                     "choice": 1})
        self.assertEqual(code, 200, receipt)
        self.assertEqual((self.row()["answer"], json.loads(self.row()["chose"])), ("B", [1]))

    def test_his_own_words_are_also_his_reply_and_a_question_back_gets_a_new_item(self):
        """The owner, 13 November 2026: "lets use the free-type text input as the general reply too, so we can remove
        the discuss option completely". Words close the item as every answer does, and the manager reads how to
        reply to a question back: with a new item, where the owner answered."""
        self.raise_item(options=["Read on both", "Read on one"])
        code, receipt = self.request("/ui/needs/1", self.command(answer="Does read on the second one show anything?"))
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.row()["answer"], "Does read on the second one show anything?")
        said = hub.t_read_messages("manager", {})
        self.assertIn("[owner] Answer to Needs-you N-1 (Which name?): Does read on the second one show anything? The "
                      "owner wrote this in their own words. If it asks you something back or does not settle the "
                      "item, reply with a new item (raise_needs_you) whose why answers what they asked.", said)
        self.assertNotRegex(said, r"\b(he|his|him)\b")                 # the hub's words name no owner "he"
        # a press is the agent's own words, so it gets no such sentence
        self.raise_item(options=["Tide", "Harbour"])
        self.assertEqual(self.request("/ui/needs/2", self.command(choice=1))[0], 200)
        self.assertNotIn("their own words", hub.t_read_messages("manager", {}))

    def test_an_item_of_another_agent_gets_no_word_about_a_new_item(self):
        """raise_needs_you is the manager's, so the words of an answer to another agent's item name no such step."""
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by) VALUES(1,'Pick a region','For the new server.',"
              "'Press one',?,'dev')", (hub.now(),))
        self.assertEqual(self.request("/ui/needs/1", self.command(answer="Why two regions?"))[0], 200)
        said = hub.q1("SELECT text FROM events WHERE agent='dev' ORDER BY id DESC")["text"]
        self.assertTrue(said.startswith("[owner] Answer to Needs-you N-1 (Pick a region): Why two regions?"), said)
        self.assertNotIn("raise_needs_you", said)

    def test_discuss_is_gone_from_the_route_and_the_tools(self):
        self.raise_item()
        code, _ = self.request("/ui/needs/1/talk", {"request_id": str(uuid.uuid4()), "db": "test-generation",
                                                     "text": "Why now?"})
        self.assertEqual(code, 404)
        self.assertNotIn("discuss_need", [t[1] for t in hub.TOOLS])
        self.assertNotIn("discuss_need", [t["name"] for t in hub.CAPP_TOOLS])
        self.assertIsNone(self.row()["answer"])

    def test_a_replaced_item_takes_the_record_of_its_earlier_discussion_along(self):
        self.raise_item(options=["A", "B"])
        hub.q("INSERT INTO need_talk(need, ts, who, text) VALUES(1, ?, 'owner', 'Can you add a third way?')",
              (hub.now(),))                                             # a record from before 13 November 2026
        out = hub.t_raise_needs_you("manager", {"title": "Which name now?", "why": "With the third way.",
                                                "what_to_do": "Press one", "options": ["A", "B", "C"],
                                                "replaces": "N-1"})
        self.assertIn("Raised N-2", out)
        self.assertEqual(self.row(1)["answer"], "Replaced by manager with a new item: Which name now?")
        self.assertEqual([t["text"] for t in self.item(2)["talk"]], ["Can you add a third way?"])
        self.assertEqual(hub.need_talk(1), [])
        with self.assertRaisesRegex(hub.ToolError, "closed already"):
            hub.t_raise_needs_you("manager", {"title": "Again", "why": "W", "what_to_do": "P", "replaces": "N-1"})

    def test_a_question_s_words_go_behind_details_with_no_code(self):
        task = hub.ins("INSERT INTO tasks(title, owner, requester, state, created) VALUES(?,?,?,?,?)",
                       ("Survey", "dev", "manager", "input-required", hub.now()))
        qid = hub.ins("INSERT INTO questions(task, asker, requester, text, asked) VALUES(?,?,?,?,?)",
                      (task, "dev", "manager", "I need read on the repository.", hub.now()))
        self.raise_item(question_id=f"Q-{qid}")
        item = self.item()
        self.assertNotIn("Quoting", item["why"])
        self.assertEqual(item["details"], "Dev's question, in its own words: \"I need read on the repository.\"")
        self.assertIsNone(hub.NEED_CODES.search(item["why"] + item["details"]))
        self.assertIn("need_talk", hub.ui_features())

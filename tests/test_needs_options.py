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
from unittest import mock

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
                                                      "what_to_do": "Press one", "reason": "person"}, **extra))

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


    def test_the_agent_recommends_one_option_or_its_own_few_words(self):
        """Owner API 1.269 (the owner, 20 November 2026: "the model should recommend one response", and his pick B of
        three pictures): the answer that the agent recommends is one of its options, word for word, or on an item with
        no options one line of its own words, which the state gives the apps; any other value is refused, and an item
        with none says null."""
        def nid(said):
            return int(said.split("N-")[1].split(".")[0])
        picked = nid(self.raise_item(title="Which colour?", options=["Blue", "Green"], recommended="Green"))
        words = nid(self.raise_item(title="What do we tell them?", recommended=" No refund, a store credit "))
        none = nid(self.raise_item(title="Which day?", options=["Monday", "Friday"]))
        self.assertEqual([self.item(n)["recommended"] for n in (picked, words, none)],
                         ["Green", "No refund, a store credit", None])
        for bad, refusal in ((dict(options=["Blue", "Green"], recommended="Red"), "one of options, word for word"),
                             (dict(recommended="two\nlines"), "one line"),
                             (dict(recommended="x" * 121), "at most 120 characters"),
                             (dict(recommended=["Blue"]), "the answer that you recommend")):
            with self.subTest(refusal=refusal), self.assertRaises(hub.ToolError) as refused:
                self.raise_item(title="Which one now?", **bad)
            self.assertIn(refusal, str(refused.exception))
        self.assertIn("need_recommended", self.request()[1]["ui_features"])
        # an option matches in any case and keeps its own words; free words get an option's checks
        case = nid(self.raise_item(title="Which size?", options=["Small", "Large"], recommended="large"))
        self.assertEqual(self.item(case)["recommended"], "Large")
        self.register("Synthetic-Login-Value-77")
        for said, refusal in (("Close T-61 first", "in plain words"),
                              ("Use Synthetic-Login-Value-77", "login")):
            with self.subTest(refusal=refusal), self.assertRaises(hub.ToolError) as refused:
                self.raise_item(title="What now?", recommended=said)
            self.assertIn(refusal, str(refused.exception))
        # a press of the recommended words is the agent's words, not the owner's typed ones (CARD_TYPED)
        row = self.row(words)
        self.assertEqual(hub.need_words_note(row, None, None, "No refund, a store credit", "app"),
                         " The owner pressed the answer that you recommended.")
        self.assertIn("in their own words", hub.need_words_note(row, None, None, "Refund it all", "app"))


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

    def test_the_board_takes_a_written_answer_only_on_an_item_with_no_options(self):
        """The review of 20 November 2026, issue 4: since the owner key, only a program posts to the board, so its
        words close no card that has its own answers, as on /ui/needs/<id> (card_words_from_tool); a press still
        goes, and words still answer an item with no options."""
        # the board's hand: a program's on a hub that holds the Mac's key (no browser sends it), the owner's on one
        # that holds none (this test hub holds none)
        with mock.patch.object(hub, "owner_key", lambda: {"sha256": "0" * 64}):
            self.assertEqual(hub.board_hand(), "other")
        self.assertIsNone(hub.board_hand())
        keyed = mock.patch.object(hub, "board_hand", lambda: "other")      # a hub that holds the Mac's key
        keyed.start()
        self.addCleanup(keyed.stop)
        self.raise_item(options=["Tide", "Harbour"])
        self.assertEqual(self.form("/needs/1", {"answer": "Call it Anchor"}), 303)
        self.assertIsNone(self.row()["answer"])
        self.assertEqual(self.form("/needs/1", {"choice": "1"}), 303)
        self.assertEqual((self.row()["answer"], self.row()["chosen"]), ("Harbour", 1))
        said = hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC")["text"]
        self.assertTrue(said.startswith("[owner via program] Answer to Needs-you N-1 (Which name?): Harbour"), said)
        self.assertIn(hub.NEED_PROGRAM_PRESSED, said)
        self.raise_item(title="Name?")
        self.assertEqual(self.form("/needs/2", {"answer": "Call it Anchor"}), 303)
        self.assertEqual(self.row(2)["answer"], "Call it Anchor")
        self.assertIn(hub.NEED_PROGRAM_WORDS, hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC")["text"])
        self.form("/say", {"text": "Ship it today."})
        self.assertEqual(hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC")["text"],
                         "[owner via program] Ship it today.")
        # a hub that holds no owner key: the owner's own browser may use the board, so its words are his
        keyed.stop()
        self.raise_item(title="Colour?", options=["Blue", "Green"])
        self.assertEqual(self.form("/needs/3", {"answer": "Red"}), 303)
        self.assertEqual(self.row(3)["answer"], "Red")
        self.assertTrue(hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC")["text"].startswith(
            "[owner] Answer to Needs-you N-3"))

    def test_the_board_refuses_a_press_that_names_no_option(self):
        self.raise_item(options=["Tide", "Harbour"])
        self.assertEqual(self.form("/needs/1", {"choice": "7"}), 303)
        self.assertIsNone(self.row()["answer"])

    def test_give_is_pressed_in_founderizer_and_never_on_the_board(self):
        """The lane "Give on a card": the board makes no grant, so its Give, pressed or written, closes nothing that
        it did not give; No still answers."""
        nid = hub.ins("INSERT INTO needs(title,why,todo,raised,by,options,give_agent,give_level,give_repos) "
                      "VALUES(?,?,?,?,'manager',?,'dev','write',?)",
                      ("Let Dev write to acme/web", "Its fix needs acme/web.", "Press Give.", hub.now(),
                       json.dumps(["Give Dev write", "No"]), json.dumps(["acme/web"])))
        self.assertEqual(self.form(f"/needs/{nid}", {"choice": "0"}), 303)
        self.assertEqual(self.form(f"/needs/{nid}", {"answer": "Give Dev write"}), 303)
        self.assertIsNone(self.row(nid)["answer"])
        self.assertEqual(self.form(f"/needs/{nid}", {"choice": "1"}), 303)
        self.assertEqual(self.row(nid)["answer"], "No")

    def test_an_item_without_options_draws_no_button(self):
        self.raise_item()
        page = self.page()
        self.assertNotIn("name='choice'", page)
        self.assertIn("name='answer'", page)


if __name__ == "__main__":
    unittest.main()


class Talk(NeedsCase):
    """Owner feature need_talk (the owner, 9 November 2026): a short card with its long part behind Details and no code,
    and options that combine. Its Discuss left the apps on 13 November 2026, and his own words answer; since 20
    November 2026 he may also ask under a card with Needs clarification (need_clarify), which keeps it open."""

    def test_a_card_is_short_and_its_long_part_goes_behind_details(self):
        with self.assertRaisesRegex(hub.ToolError, "The title is at most 70 characters"):
            self.raise_item(title="x" * 71)
        with self.assertRaisesRegex(hub.ToolError, "why is at most 240 characters.*Put the reasoning"):
            self.raise_item(why="y " * 121)
        with self.assertRaisesRegex(hub.ToolError, "what_to_do is at most 4000 characters"):     # read under a lock
            self.raise_item(what_to_do="Press one. " * 400)
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

    def test_a_command_in_a_code_block_is_literal_and_the_words_around_it_are_not(self):
        # the owner, 15 November 2026: "manager tasks need to be super specific. Like run "xxx"". Since 17 November
        # no item gives the owner a command to run (test_card_reasons), so a block stands in details and on the door's
        # card, and the words around it are read as before.
        command = "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem"
        self.raise_item(details=f"The agent ran, in the folder of the shop:\n\n```\n{command}\n```")
        self.assertIn(command, self.item()["details"])              # as written: the card draws the block
        with self.assertRaisesRegex(hub.ToolError, "Say P-256 in plain words"):
            self.raise_item(what_to_do=f"On your Mac, run {command}")                   # in a line of words
        with self.assertRaisesRegex(hub.ToolError, "Say T-61 in plain words"):
            self.raise_item(what_to_do=f"For T-61, run:\n\n```\n{command}\n```")      # a hub code beside the block
        with self.assertRaisesRegex(hub.ToolError, "Say Q-59 in plain words"):
            self.raise_item(what_to_do=f"Run:\n\n```\n{command}\n```\n\nThen answer Q-59.")
        with self.assertRaisesRegex(hub.ToolError, "Say R-3 in plain words"):
            self.raise_item(what_to_do="Run `fleet R-3` on your Mac.")                   # code in a line is read
        # a block ends where the apps end it: at the first line that begins with three backticks
        with self.assertRaisesRegex(hub.ToolError, "Say T-61 in plain words"):
            self.raise_item(what_to_do="Run:\n```\nx\n```y\nFor T-61 do this\n```")
        with self.assertRaisesRegex(hub.ToolError, "Say T-61 in plain words"):
            self.raise_item(what_to_do="Run:\n```\nx\n\u00a0```\nFor T-61 do this\n```")
        with self.assertRaisesRegex(hub.ToolError, "Say P-256 in plain words"):
            self.raise_item(what_to_do=f"Run:\n\n```\n{command}")                      # a block that never ends
        # a title, a reason and an option are words only: a block there hides nothing
        for field, value in (("title", "```\nT-61\n```"), ("why", "```\nT-61\n```"),
                             ("options", ["```\nT-61\n```", "No"])):
            with self.subTest(field=field), self.assertRaises(hub.ToolError):
                self.raise_item(**{field: value})
        self.raise_item(details=f"The key is made with:\n\n```\n{command}\n```")      # the details draw a block too

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
        reply to a question back: with a new item, where the owner answered. Since 17 November 2026 the same words
        send the manager to the line that sent a card that went the wrong way, before its next card."""
        self.raise_item(options=["Read on both", "Read on one"])
        code, receipt = self.request("/ui/needs/1", self.command(answer="Does read on the second one show anything?"))
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.row()["answer"], "Does read on the second one show anything?")
        said = hub.t_read_messages("manager", {})
        self.assertIn("[owner] Answer to Needs-you N-1 (Which name?): Does read on the second one show anything? The "
                      "owner wrote this in their own words. If it asks you something back or does not settle the "
                      "item, reply with a new item (raise_needs_you) whose why answers what they asked. If it says "
                      "that the item was not needed or went the wrong way, find the line that sent it (a policy, a "
                      "profile, a standing item, your notes) and correct it before your next item", said)
        self.assertNotRegex(said, r"\b(he|his|him)\b")                 # the hub's words name no owner "he"
        # a press is the agent's own words, so it gets no such sentence
        self.raise_item(options=["Tide", "Harbour"])
        self.assertEqual(self.request("/ui/needs/2", self.command(choice=1))[0], 200)
        self.assertNotIn("their own words", hub.t_read_messages("manager", {}))
        # The review of 20 November 2026, issue 4: card N-230 was answered in the owner's voice by a Claude Code
        # session through founderizer-cli, the hub said "The owner wrote this in their own words", and the manager kept
        # the words as the owner's rule. Words that the owner tools send (their label, or a request that names its
        # session) are an AI session's: the hub says so to the agent, and the row keeps who sent them.
        tool = {"Content-Type": "application/json", "X-Fleet-Client": "founderizer-cli/1/test",
                "X-Fleet-Session": "claude-code/0d8aa41c"}
        self.raise_item(title="Add swap?")                      # N-3: no options, so words are its only answer
        code, receipt = self.request("/ui/needs/3", self.command(answer="Not my decision: Leo's call from now on."),
                                     headers=tool)
        self.assertEqual(code, 200, receipt)
        said = hub.t_read_messages("manager", {})
        self.assertIn("[owner via ai-session] Answer to Needs-you N-3 (Add swap?): Not my decision: Leo's call from "
                      "now on." + hub.NEED_TOOL_WORDS + hub.NEED_TOOL_RULE, said)
        self.assertNotIn("their own words", said)
        self.assertEqual([tuple(r) for r in hub.q("SELECT need_id, hand, session FROM ui_requests ORDER BY need_id")],
                         [(1, "app", None), (2, "app", None), (3, "tool", "claude-code/0d8aa41c")])
        # the program's label alone is enough, and a session's press says that a session pressed it
        self.raise_item(title="Window?", options=["Go to 80", "Stay at 70"])        # N-4
        code, receipt = self.request("/ui/needs/4", self.command(choice=0), headers={
            "Content-Type": "application/json", "X-Fleet-Client": "founderizer-mcp/1/test"})
        self.assertEqual(code, 200, receipt)
        self.assertIn("[owner via ai-session] Answer to Needs-you N-4 (Window?): Go to 80" + hub.NEED_TOOL_PRESSED,
                      hub.t_read_messages("manager", {}))
        # and words to a card that has its own answers are refused: the card stays open for the owner (N-230 had three)
        self.raise_item(title="Raise it?", options=["Go to 80", "Stay at 70"])      # N-5
        code, refused = self.request("/ui/needs/5", self.command(answer="Not my decision: go ahead."), headers=tool)
        self.assertEqual((code, refused.get("code"), self.row(5)["answer"]), (409, "card_words_from_tool", None))
        self.assertEqual(self.request("/ui/needs/5", self.command(choice=1), headers=tool)[0], 200)
        self.assertEqual(self.row(5)["answer"], "Stay at 70")
        # a session that is no name is refused before anything is written
        self.raise_item(title="Region?")                        # N-6
        code, _ = self.request("/ui/needs/6", self.command(answer="West"), headers=dict(tool, **{
            "X-Fleet-Session": "claude code/1"}))
        self.assertEqual((code, self.row(6)["answer"]), (400, None))
        # the hands of the labels: the Mac app's screen, the owner tools, a connected app, anything else
        self.assertEqual([hub.request_hand(c) for c in ("founderizer-swift/1/a", "founderizer-cli/1/a",
                                                        "founderizer-mcp/1/a", "connected:3", "deterministic-test")],
                         ["app", "tool", "tool", "other", "other"])        # a connected app's label alone is a claim
        self.assertEqual(hub.request_hand("connected:3", connection={"id": 3, "name": "Claude"}), "connected")
        self.assertEqual(hub.request_hand("deterministic-test", session="claude-code/1"), "tool")
        # a session that names itself is a tool from an enrolled device too, and the PC app's label is the owner's
        self.assertEqual(hub.request_hand("founderizer-swift/1/a", device="Windows", session="claude-code/1"), "tool")
        self.assertEqual(hub.request_hand("founderizer-windows/1/a"), "app")
        # Owner API 1.325: the release job's label is the hand "job", also when a session runs the job by hand, and a
        # connected app's record and a chat app's origin still come first. Bug: a session that runs the job makes its
        # words a session's, which the owner's chat shows as his own message again. On an enrolled device the label is
        # a program's: bug, a program on a PC makes a hidden note that says it is the owner's Mac's
        release = "founderizer-release/1/a"
        self.assertEqual([hub.request_hand(release), hub.request_hand(release, session="claude-code/1"),
                          hub.request_hand(release, device="Windows"),
                          hub.request_hand(release, connection={"id": 3, "name": "Claude"}),
                          hub.request_hand(release, origin={"app": "whatsapp"})],
                         ["job", "job", "other", "connected", "chat"])
        # Fable's check of 20 November 2026, finding 1: a label that no app of the owner's gives (here curl's) has no
        # owner's force either: its words close no card that has its own answers, and its words to an item with none
        # are a program's, never the owner's own. So are the release job's (owner API 1.325 on each route but POST
        # /ui/messages): bug, request_via gives the hand "job" no mark, and its answer reads "[owner]", his own words
        for label, card in (("curl/8.7.1", 7), (release, 9)):
            program = {"Content-Type": "application/json", "X-Fleet-Client": label}
            self.raise_item(title="Window again?", options=["Go to 80", "Stay at 70"])     # N-7, N-9
            code, refused = self.request(f"/ui/needs/{card}", self.command(answer="Go ahead, Leo decides."),
                                         headers=program)
            self.assertEqual((code, refused.get("code"), self.row(card)["answer"]),
                             (409, "card_words_from_tool", None), label)
            self.raise_item(title="Disk?")                          # N-8, N-10
            self.assertEqual(self.request(f"/ui/needs/{card + 1}", self.command(answer="Add one."),
                                          headers=program)[0], 200, label)
            said = hub.t_read_messages("manager", {})
            self.assertIn(f"[owner via program] Answer to Needs-you N-{card + 1} (Disk?): Add one."
                          + hub.NEED_PROGRAM_WORDS, said)
            self.assertNotIn("their own words", said)

    def test_an_item_of_another_agent_gets_no_word_about_a_new_item(self):
        """raise_needs_you is the manager's, so the words of an answer to another agent's item name no such step."""
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by) VALUES(1,'Pick a region','For the new server.',"
              "'Press one',?,'dev')", (hub.now(),))
        self.assertEqual(self.request("/ui/needs/1", self.command(answer="Why two regions?"))[0], 200)
        said = hub.q1("SELECT text FROM events WHERE agent='dev' ORDER BY id DESC")["text"]
        self.assertTrue(said.startswith("[owner] Answer to Needs-you N-1 (Pick a region): Why two regions?"), said)
        self.assertNotIn("raise_needs_you", said)

    def test_needs_clarification_keeps_the_card_open_and_the_manager_replies_under_it(self):
        """Owner feature need_clarify (owner API 1.272; the owner, 20 November 2026: "a button link, that then shows the
        extra text input", and "Keep Your answer too"): his message under the card keeps the item open and reaches
        the manager with the hub's line on how to reply; the manager's reply joins the card's talk and rings his phone
        as a card does; his answer still closes the item, and then the card takes no more."""
        self.raise_item(options=["Tide", "Harbour"])
        self.assertTrue(self.item()["clarify"])
        self.assertIn("need_clarify", hub.ui_features())
        code, receipt = self.request("/ui/needs/1/talk", self.command(text="  Which one costs less?  "))
        self.assertEqual(code, 200, receipt)
        self.assertEqual((receipt["need"], [(t["who"], t["text"]) for t in receipt["talk"]]),
                         (1, [("owner", "Which one costs less?")]))
        self.assertIsNone(self.row()["answer"])
        said = hub.t_read_messages("manager", {})
        self.assertIn("[owner] About Needs-you N-1 (Which name?), before answering it: Which one costs less?", said)
        self.assertIn('discuss_need(need="N-1", text=...)', said)
        self.assertIn('raise_needs_you(replaces="N-1")', said)
        with mock.patch.object(hub, "ping_reply") as ping:
            out = hub.t_discuss_need("manager", {"need": "N-1", "text": "Harbour costs 4 euros less a month."})
        ping.assert_called_once_with(hub.q1("SELECT id FROM need_talk WHERE who='manager'")["id"])   # the reply's ring
        self.assertIn("Your reply is under N-1", out)
        self.assertIn("replied about: Which name?",
                      hub.q1("SELECT text FROM events WHERE agent='owner' AND kind='notify' ORDER BY id DESC")["text"])
        self.assertEqual([(t["who"], t["text"]) for t in self.item()["talk"]],
                         [("owner", "Which one costs less?"), ("manager", "Harbour costs 4 euros less a month.")])
        self.assertEqual(self.request("/ui/needs/1", self.command(choice=1))[0], 200)
        self.assertEqual(self.row()["answer"], "Harbour")
        self.assertFalse(self.item()["clarify"])
        self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="And now?"))[0], 409)
        # The review of 20 November 2026, issue 4 (Fable's third check): an AI session's talk under a card says so in
        # its header and in one sentence, as its answer does
        self.raise_item(title="Which window?", options=["80", "70"])
        code, receipt = self.request("/ui/needs/2/talk", self.command(text="Is 80 safe?"), headers={
            "Content-Type": "application/json", "X-Fleet-Client": "founderizer-cli/1/test",
            "X-Fleet-Session": "claude-code/0d8aa41c"})
        self.assertEqual(code, 200)
        # Owner feature message_hands (UI-API.md 1.332): the route's answer gives the hand of each entry and the AI
        # program of its session, so that the app draws the outlined bubble with the AI's mark at once. Bug: need_talk
        # gives who, text and ts only, and the session's words stand in his filled bubble until the next read.
        self.assertEqual([(t["who"], t["hand"], t["runtime"]) for t in receipt["talk"]],
                         [("owner", "tool", "claude-code")])
        said = hub.t_read_messages("manager", {})
        self.assertIn("[owner via ai-session] About Needs-you N-2 (Which window?), before answering it: Is 80 safe?",
                      said)
        self.assertIn(hub.NEED_TALK_NOT_HIS, said)
        # and a program's (any label that no app of the owner's gives)
        code, _ = self.request("/ui/needs/2/talk", self.command(text="And 75?"), headers={
            "Content-Type": "application/json", "X-Fleet-Client": "curl/8.7.1"})
        self.assertEqual(code, 200)
        said = hub.t_read_messages("manager", {})
        self.assertIn("[owner via program] About Needs-you N-2 (Which window?), before answering it: And 75?", said)
        self.assertIn(hub.NEED_TALK_NOT_HIS, said)
        with self.assertRaisesRegex(hub.ToolError, "answered already"):
            hub.t_discuss_need("manager", {"need": "N-1", "text": "Late."})
        # The card's talk in GET /ui/state and GET /ui/mobile (need_reads) gives the same: his own words and an agent's
        # reply have null in both, and the session's id is in no answer. Bugs: need_reads drops the hand (the card
        # shows the session's words as his), gives an agent's reply a hand or a runtime, or gives the session's id.
        with mock.patch.object(hub, "ping_reply"):
            hub.t_discuss_need("manager", {"need": "N-2", "text": "Both are safe, and 80 is faster."})
        mobile = self.request("/ui/mobile")[1]
        talks = {"state": (self.item(1)["talk"], self.item(2)["talk"]),
                 "mobile": tuple(next(n for n in mobile["needs"] + mobile["answered_needs"] if n["id"] == nid)["talk"]
                                 for nid in (1, 2))}
        for read, (first, second) in talks.items():
            self.assertEqual([(t["who"], t["hand"], t["runtime"]) for t in first],
                             [("owner", None, None), ("manager", None, None)], read)
            self.assertEqual([(t["who"], t["hand"], t["runtime"]) for t in second],
                             [("owner", "tool", "claude-code"), ("owner", "other", None), ("manager", None, None)],
                             read)
        # the rows: a session only with words that he did not type, and none with his own (the Mac app's)
        self.assertEqual([tuple(r) for r in hub.q("SELECT text, hand, session FROM need_talk WHERE who='owner' "
                                                  "ORDER BY id")],
                         [("Which one costs less?", None, None), ("Is 80 safe?", "tool", "claude-code/0d8aa41c"),
                          ("And 75?", "other", None)])
        self.assertNotIn("0d8aa41c", json.dumps(self.request()[1]) + json.dumps(mobile))

    def test_the_manager_replies_once_until_the_owner_writes_again(self):
        """The area's word of 20 November 2026: one reply to each message of the owner's, so that no loop of replies
        rings his phone again and again; his next message opens the next reply."""
        self.raise_item(options=["Tide", "Harbour"])
        with self.assertRaisesRegex(hub.ToolError, r"no new message of the owner's to reply to.*replaces=\"N-1\""):
            hub.t_discuss_need("manager", {"need": "N-1", "text": "Before you ask: Harbour costs less."})
        self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="Which one costs less?"))[0], 200)
        with mock.patch.object(hub, "ping_reply") as ping:
            hub.t_discuss_need("manager", {"need": "N-1", "text": "Harbour, by 4 euros a month."})
            with self.assertRaisesRegex(hub.ToolError, "Wait for their next message there"):
                hub.t_discuss_need("manager", {"need": "N-1", "text": "Also, Harbour is closer."})
            self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="And the setup?"))[0], 200)
            hub.t_discuss_need("manager", {"need": "N-1", "text": "One hour for both."})
        self.assertEqual(ping.call_count, 2)
        self.assertEqual([t["who"] for t in self.item()["talk"]], ["owner", "manager", "owner", "manager"])

    def test_a_card_waits_for_the_manager_until_it_answers_or_two_turns_end_with_no_answer(self):
        """Owner API 1.316, feature need_updates (the owner, 22 November 2026: after his Needs clarification message
        the options go "until the agent decides what's next"). His message makes the card wait (awaits) while the
        manager can have a turn; its reply ends the wait; a manager that reads his words and ends two turns with no
        answer, or that cannot have a turn any more, ends it too, and the next second look names the card. Bug: a card
        that hides its options for ever because the manager's session was gone or never answered, or one that waits
        for a manager at a usage limit."""
        hub.touch("manager")                                  # its helper is online
        hub.kv_set("turn_ended:manager", hub.now() - 100)     # and reports turn ends
        self.raise_item(options=["Tide", "Harbour"])
        self.assertIn("need_updates", hub.ui_features())
        self.assertIsNone(self.item()["awaits"])
        self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="Which one costs less?"))[0], 200)
        self.assertEqual(self.item()["awaits"], hub.need_talk(1)[0]["ts"])
        said = hub.t_read_messages("manager", {})
        self.assertIn("(The hub: the item stays open, and its card waits for your answer. Answer the owner in one of "
                      "three ways: reply under the card with discuss_need(need=\"N-1\", text=...), in plain words "
                      "and in a few sentences, when the request stays as it is; raise it again with "
                      "raise_needs_you(replaces=\"N-1\") when its words or options change; or close it with "
                      "withdraw_need(need=\"N-1\", why=...) when nothing in it is needed now, and the owner reads why "
                      "under the card. Their answer to the item comes as its own message.)", said)
        hub.t_discuss_need("manager", {"need": "N-1", "text": "Harbour, by 4 euros a month."})
        self.assertIsNone(self.item()["awaits"])                # the reply: the same request again
        # his next message, which the manager reads and leaves with no answer for two turns
        self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="And the setup?"))[0], 200)
        hub.need_wait_sweep(hub.now())
        hub.t_read_messages("manager", {})
        hub.need_wait_sweep(hub.now())                          # the turn that read it still runs
        asks = lambda: [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' AND "
                                                 "text LIKE '[hub] The owner''s words under%' ORDER BY id")]
        self.assertEqual(asks(), [])
        hub.kv_set("turn_ended:manager", hub.now())             # a turn ended after its read
        hub.need_wait_sweep(hub.now())
        hub.need_wait_sweep(hub.now())
        # his words quoted, as no tool of the manager's reads a card's talk (the area's reader)
        ask = ("[hub] The owner's words under Needs-you N-1 (Which name?) have no answer from you yet, and its card "
               "waits for one. Their newest words there, quoted: \"{}\".{} " + hub.need_wait_ways(self.row()) +
               " If your next turn ends with none of these, the card stops waiting for you, and a later second look "
               "names it.")
        self.assertEqual(asks(), [ask.format("And the setup?", "")])        # once
        # a message of his while the ask waits makes a wait of its own, with its own ask: bug, the old ask ends the new
        # wait at the next turn end with no word to the manager. An AI session wrote this one, and both the ask and the
        # look say that its words are not the owner's (need_talk.hand): bug, the hub's line calls them the owner's
        self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="And who sets it up?"), headers={
            "Content-Type": "application/json", "X-Fleet-Client": "founderizer-cli/1/test"})[0], 200)
        hub.t_read_messages("manager", {})
        hub.kv_set("turn_ended:manager", hub.now())
        hub.need_wait_sweep(hub.now())
        self.assertEqual(asks(), [ask.format("And the setup?", ""), ask.format("And who sets it up?",
                                                                                 hub.NEED_TALK_NOT_HIS)])
        self.assertIsNotNone(self.item()["awaits"])
        hub.t_read_messages("manager", {})
        hub.need_wait_sweep(hub.now())
        self.assertIsNotNone(self.item()["awaits"])             # the turn that read the ask still runs
        hub.kv_set("turn_ended:manager", hub.now())
        hub.tick()                                              # the hub's own pass ends it (and gives the look)
        self.assertIsNone(self.item()["awaits"])
        self.assertEqual([t["who"] for t in self.item()["talk"]], ["owner", "manager", "owner", "owner"])     # kept
        looks = lambda: [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' AND "
                                                  "text LIKE '[hub] A second look%' ORDER BY id")]
        t0 = hub.now()
        hub.need_look_sweep(t0)                                 # a card of a minute ago: named for this alone
        self.assertEqual(len(looks()), 1)
        mark = hub.NEED_TALK_NOT_HIS.strip().rstrip(".")
        mark = mark[0].lower() + mark[1:]
        self.assertIn(f'- N-1 "Which name?", yours, open 0 hours: the owner\'s words under it have no reply (quoted: '
                      f'"And who sets it up?"; {mark}): reply there with discuss_need, raise it again with '
                      f'raise_needs_you replaces or close it with withdraw_need.', looks()[0])
        hub.need_look_sweep(t0 + 120)
        self.assertEqual(len(looks()), 1)                       # once, then at its own time
        # a reply after the hub's ask ends the wait for good: bug, the ask that stays makes the next look name an
        # answered card as one whose words have no reply
        self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="Is it ready?"))[0], 200)
        hub.t_read_messages("manager", {})
        hub.kv_set("turn_ended:manager", hub.now())
        hub.need_wait_sweep(hub.now())
        self.assertEqual(len(asks()), 3)
        hub.t_discuss_need("manager", {"need": "N-1", "text": "Yes, since this morning."})
        hub.need_look_sweep(t0 + 240)
        self.assertEqual(len(looks()), 1)
        # a card whose manager cannot have a turn any more (its helper went away) waits no more either
        self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="Still there?"))[0], 200)
        self.assertIsNotNone(self.item()["awaits"])
        hub.q("UPDATE agents SET last_seen=? WHERE name='manager'", (hub.now() - 3600,))
        hub.need_wait_sweep(hub.now())
        self.assertIsNone(self.item()["awaits"])
        # a door card has no replaces among the ways, and his answer still closes a card that waits
        hub.touch("manager")
        t0 = hub.now()
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,options,door_call,door_host) VALUES(2,'Run one root "
              "script on web-1?','It reads the logs.','Press Run it once',?,'manager',?,?,'web-1')",
              (t0, json.dumps(["Run it once", "No"]), "a" * 64))
        self.assertEqual(self.request("/ui/needs/2/talk", self.command(text="Why root?"))[0], 200)
        self.assertIn("Answer the owner in one of two ways: reply under the card with discuss_need(need=\"N-2\"",
                      hub.t_read_messages("manager", {}))
        self.assertIsNotNone(self.item(2)["awaits"])
        self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="Which one is closer?"))[0], 200)
        self.assertIsNotNone(self.item()["awaits"])
        self.assertEqual(self.request("/ui/needs/1", self.command(choice=1))[0], 200)
        self.assertEqual((self.item()["answer"], self.item()["awaits"]), ("Harbour", None))
        # a card that only the hub or his phone closes does not wait: the manager neither withdraws it nor sees it in a
        # second look (an App key's renewal, a server's key swap, a phone to add)
        for nid, column, value in ((4, "github_key", "acme"), (5, "key_swap_server", "web-2"), (6, "add_device", 1)):
            with self.subTest(kind=column):
                hub.q(f"INSERT INTO needs(id,title,why,todo,raised,by,{column}) VALUES(?,'A card','Its why',"
                      "'Press one',?,'manager',?)", (nid, hub.now(), value))
                self.assertEqual(self.request(f"/ui/needs/{nid}/talk", self.command(text="Why now?"))[0], 200)
                self.assertIsNone(self.item(nid)["awaits"])
                said = hub.t_read_messages("manager", {})
                self.assertIn(f'discuss_need(need="N-{nid}", text=...), in plain words and in a few sentences. Their '
                              f'answer to the item comes as its own message.)', said)        # the line as before
                self.assertNotIn(f'withdraw_need(need="N-{nid}"', said)
        # a manager at a usage limit: his message goes to it as before, and the card does not wait
        hub.q("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('manager',?,?,1)",
              (hub.now(), hub.now() + 3600))
        self.raise_item(title="Which day?", options=["Monday", "Friday"])
        self.assertEqual(self.request("/ui/needs/7/talk", self.command(text="Why Monday?"))[0], 200)
        self.assertIsNone(self.item(7)["awaits"])
        self.assertIn("(The hub: the item stays open. Reply under the card with discuss_need(need=\"N-7\", text=...)",
                      hub.t_read_messages("manager", {}))

    def test_an_ai_sessions_message_from_before_the_hand_keeps_its_mark(self):
        """Owner API 1.316: a message under a card from before need_talk.hand has no hand, which reads as the owner's
        own words. Bug: the second look quotes an old message of an AI session or a program as the owner's words with
        no mark, at each look while the card stays open. The one-time repair at the start reads each one's line to
        the manager, which has carried the mark since 21 November 2026; a row whose line has no mark, or that has no
        line, stays his own words, and a second start changes nothing."""
        self.raise_item(options=["Tide", "Harbour"])
        hub.need_talk_said({"need": 1, "text": "Is it cheaper?"}, hand="app")        # his own: its line has no mark
        hub.ins("INSERT INTO need_talk(need, ts, who, text) VALUES(1, ?, 'owner', 'From the old Discuss box')",
                (hub.now(),))                                                       # no line to the manager
        hub.need_talk_said({"need": 1, "text": "And next month?"}, hand="other")   # a program's
        hub.need_talk_said({"need": 1, "text": "Drop that vendor"}, hand="tool")   # an AI session's
        hub.q("UPDATE need_talk SET hand=NULL")                     # as a release before the column wrote them
        hands = lambda: [(r["text"], r["hand"]) for r in hub.q("SELECT text, hand FROM need_talk ORDER BY id")]
        look = lambda: hub.need_look_hints(self.row())[0]
        self.assertNotIn("an AI session", look())                   # the fault
        hub.settle_talk_hands()
        self.assertEqual(hands(), [("Is it cheaper?", None), ("From the old Discuss box", None),
                                   ("And next month?", "other"), ("Drop that vendor", "tool")])
        self.assertIn('(quoted: "Drop that vendor"; an AI session or a program on the owner\'s Mac wrote these words',
                      look())
        self.assertEqual(hub.kv_get(hub.TALK_HANDS_SETTLED), "2")
        hub.q("UPDATE need_talk SET hand=NULL WHERE text='Drop that vendor'")
        hub.settle_talk_hands()                                     # a second start
        self.assertEqual(hands()[3], ("Drop that vendor", None))

    def test_a_door_card_and_a_team_card_take_a_message_too(self):
        """The area's word of 20 November 2026: every card of the manager's takes it, a door card and a plan of team
        changes too, since the owner may ask about a script or a plan before he presses; the hub's line names no
        replaces for them, which raise_needs_you does not take the place of."""
        t0 = hub.now()
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,options,door_call,door_host) VALUES(1,'Run one root "
              "script on web-1?','It reads the logs.','Press Run it once',?,'manager',?,?,'web-1')",
              (t0, json.dumps(["Run it once", "Full access on web-1", "No"]), "a" * 64))
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,options,team_plan) VALUES(2,'Add Nova?','For the shop.',"
              "'Press one',?,'manager',?,?)", (t0, json.dumps(["Yes: add nova", "No"]), json.dumps({"steps": []})))
        for nid in (1, 2):
            with self.subTest(item=nid):
                self.assertTrue(self.item(nid)["clarify"])
                code, receipt = self.request(f"/ui/needs/{nid}/talk", self.command(text="Why this one?"))
                self.assertEqual(code, 200, receipt)
                said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC")["text"]
                self.assertIn(f"About Needs-you N-{nid}", said)
                self.assertNotIn("replaces", said)
        # Owner API 1.316: on a card that waits, the hub's line and the second look name the calls that the card
        # takes, and on a card that takes a question to the owner they say to reply first (the area's reader, findings
        # 1 and 3). Bug: a way that the hub refuses, or the question's answer as a way, which closes the card with no
        # word to the owner, against his yes to a ring when the agent closes a card after his message; or a replace
        # with no question_id, whose new card drops the question, so that its asker waits with no card.
        hub.touch("manager")
        hub.kv_set("turn_ended:manager", hub.now() - 100)
        task = hub.ins("INSERT INTO tasks(title, owner, requester, state, created) VALUES(?,?,?,?,?)",
                       ("Export", "dev", "manager", "input-required", t0))
        qid = hub.ins("INSERT INTO questions(task, asker, requester, text, asked) VALUES(?,?,?,?,?)",
                      (task, "dev", "manager", "Which export?", t0))
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,question) VALUES(3,'Which export?','Dev asks.','Answer',?,"
              "'manager',?)", (t0, qid))
        ways = {1: ("Answer the owner in one of two ways: reply under the card with discuss_need(need=\"N-1\", "
                    "text=...), in plain words and in a few sentences, when the request stays as it is; or close it "
                    "with withdraw_need(need=\"N-1\", why=...) when nothing in it is needed now, and the owner reads why "
                    "under the card.", "reply there with discuss_need or close it with withdraw_need"),
                2: ("Answer the owner in one of three ways: reply under the card with discuss_need(need=\"N-2\", "
                    "text=...), in plain words and in a few sentences, when the request stays as it is; make a new "
                    "plan with change_team when its changes change: a new card of a plan takes this one's place; or "
                    "close it with withdraw_need(need=\"N-2\", why=...) when nothing in it is needed now, and the "
                    "owner reads why under the card.",
                    "reply there with discuss_need, make a new plan with change_team or close it with withdraw_need"),
                3: ("Answer the owner in one of two ways: reply under the card with discuss_need(need=\"N-3\", "
                    "text=...), in plain words and in a few sentences, when the request stays as it is; or raise it "
                    f"again with raise_needs_you(replaces=\"N-3\", question_id=\"Q-{qid}\") when its words or options "
                    f"change. Answering Q-{qid} closes the card with no word to the owner: reply under it first.",
                    f"reply there with discuss_need or raise it again with raise_needs_you replaces and question_id, "
                    f"as answering Q-{qid} closes the card with no word to them")}
        for nid, (line, look) in ways.items():
            with self.subTest(waits=nid):
                self.assertEqual(self.request(f"/ui/needs/{nid}/talk", self.command(text="Why now?"))[0], 200)
                self.assertIsNotNone(self.item(nid)["awaits"])
                said = hub.t_read_messages("manager", {})
                self.assertIn(f"its card waits for your answer. {line} Their answer", said)
                self.assertEqual(hub.need_look_hints(self.row(nid))[0],
                                 f'the owner\'s words under it have no reply (quoted: "Why now?"): {look}')

    def test_a_card_that_answers_by_another_route_takes_no_message_under_it(self):
        """A key request has its own Needs clarification, whose words answer it (secret_clarify), a conversation's item
        is that person's question, and only the manager replies under a card: each says so, and its clarify is
        false, so the apps draw no link there."""
        t0 = hub.now()
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,kind,secret) VALUES(1,'Add the key','Scout reads prices.',"
              "'Save it',?,'manager','secret',?)", (t0, json.dumps({"kind": "api_key", "env": "SHOP_API_KEY"})))
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,kind,conversation) VALUES(2,'Which day?','Mia asks.',"
              "'Answer',?,'manager','question',5)", (t0,))
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by) VALUES(3,'Pick a region','For the new server.',"
              "'Press one',?,'dev')", (t0,))
        for nid, line in ((1, "its own Needs clarification"), (2, "that person's question"), (3, "only the manager")):
            with self.subTest(item=nid):
                self.assertFalse(self.item(nid)["clarify"])
                code, refused = self.request(f"/ui/needs/{nid}/talk", self.command(text="Why?"))
                self.assertEqual(code, 409, refused)
                self.assertIn(line, json.dumps(refused))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM need_talk")["n"], 0)
        with self.assertRaisesRegex(hub.ToolError, "you reply only under a card that you raised"):
            hub.t_discuss_need("manager", {"need": "N-3", "text": "It is cheaper."})
        with self.assertRaisesRegex(hub.ToolError, "takes no reply under its card"):
            hub.t_discuss_need("dev", {"need": "N-3", "text": "It is cheaper."})

    def test_a_message_under_a_card_is_one_message_of_plain_words(self):
        """The route takes its text and nothing else, and a registered login never goes to the manager in it; the
        manager's reply is one message of plain words, with no code, and asks for no key's value, which the owner's
        words under the card would hold."""
        self.raise_item()
        for body, status in ((self.command(text="   "), 400), (self.command(text="x" * 2001), 400),
                             (self.command(text="Why?", choice=0), 400)):
            with self.subTest(body=sorted(body)):
                self.assertEqual(self.request("/ui/needs/1/talk", body)[0], status)
        self.register("hunter2-for-the-test")
        self.assertEqual(self.request("/ui/needs/1/talk", self.command(text="It is hunter2-for-the-test"))[0], 422)
        self.assertEqual(hub.need_talk(1), [])
        with self.assertRaisesRegex(hub.ToolError, "Say T-12 in plain words"):
            hub.t_discuss_need("manager", {"need": "N-1", "text": "It waits on T-12."})
        with self.assertRaisesRegex(hub.ToolError, "1 to 2000 characters"):
            hub.t_discuss_need("manager", {"need": "N-1", "text": "x" * 2001})
        with self.assertRaisesRegex(hub.ToolError, "Not sent: this reply asks the owner for a key"):
            hub.t_discuss_need("manager", {"need": "N-1", "text": "Type the new API key as your answer."})

    def test_a_replaced_item_takes_the_record_of_its_earlier_discussion_along(self):
        """Bug: the talk of a replaced item stays on its closed card, or the closed card does not name the item that
        took its place, so that an app draws the hub's words "Replaced by ..." as a card of their own (owner API
        1.274)."""
        self.raise_item(options=["A", "B"])
        hub.q("INSERT INTO need_talk(need, ts, who, text) VALUES(1, ?, 'owner', 'Can you add a third way?')",
              (hub.now(),))                                             # a record from before 13 November 2026
        out = hub.t_raise_needs_you("manager", {"title": "Which name now?", "why": "With the third way.",
                                                "what_to_do": "Press one", "options": ["A", "B", "C"],
                                                "replaces": "N-1", "reason": "person"})
        self.assertIn("Raised N-2", out)
        self.assertEqual(self.row(1)["answer"], f"Replaced by {hub.shown_role('manager')} with a new item: Which name now?")
        self.assertEqual([hub.need_view(self.row(n))["replaced_by"] for n in (1, 2)], [2, None])
        self.assertEqual([t["text"] for t in self.item(2)["talk"]], ["Can you add a third way?"])
        self.assertEqual(hub.need_talk(1), [])
        with self.assertRaisesRegex(hub.ToolError, "closed already"):
            hub.t_raise_needs_you("manager", {"title": "Again", "why": "W", "what_to_do": "P", "replaces": "N-1",
                                              "reason": "person"})
        # Owner API 1.316 (need_updates): the card is a chain of versions, and its newest item gives the earlier ones,
        # oldest first, with the raise of the first. Bug: a history with a version missing or in the wrong order.
        hub.t_raise_needs_you("manager", {"title": "Which name, now with prices?", "why": "C costs more.",
                                          "what_to_do": "Press one", "options": ["A", "C"], "recommended": "A",
                                          "replaces": "N-2", "reason": "person"})
        first, second = self.row(1), self.row(2)
        self.assertEqual(self.item(3)["versions"], [
            {"id": 1, "title": "Which name?", "why": "The owner names it", "options": ["A", "B"], "recommended": None,
             "raised": first["raised"], "ended": first["answered"]},
            {"id": 2, "title": "Which name now?", "why": "With the third way.", "options": ["A", "B", "C"],
             "recommended": None, "raised": second["raised"], "ended": second["answered"]}])
        self.assertEqual(self.item(3)["since"], first["raised"])
        self.assertEqual(hub.mobile_state("test-generation")["needs"][0]["versions"], self.item(3)["versions"])
        # a replaced item gives none: its newest version gives the chain, which would else grow as n squared
        self.assertEqual((self.item(2)["versions"], self.item(2)["since"], self.item(1)["versions"],
                          self.item(1)["since"]), ([], second["raised"], [], first["raised"]))
        hub.q("DELETE FROM needs WHERE id=1")                   # a removed item: the chain starts after it
        self.assertEqual(([v["id"] for v in self.item(3)["versions"]], self.item(2)["versions"],
                          self.item(3)["since"]), ([2], [], second["raised"]))

    # each card of a question of one task beside an open one says that it is another need (P7 4.2)
    ANOTHER = "Another question of the survey."

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
        # a question of several lines keeps them on the card (20 November 2026: four lines stood as one paragraph)
        qid = hub.ins("INSERT INTO questions(task, asker, requester, text, asked) VALUES(?,?,?,?,?)",
                      (task, "dev", "manager", "Which way do I fix the check?\r\nA) Add the schema.  \n\n\n\n"
                       "B) Skip the file.\n  - one\tpart\nMy suggestion: A.\n", hub.now()))
        self.raise_item(question_id=f"Q-{qid}", also=self.ANOTHER)
        self.assertEqual(self.item(2)["details"], "Dev's question, in its own words:\n\"Which way do I fix the check?\n"
                                                  "A) Add the schema.\n\nB) Skip the file.\n  - one part\n"
                                                  "My suggestion: A.\"")
        # details that quote the question already get no second copy of it (the owner, 20 November 2026: "why is the
        # text like repeated ... I need more brevity and clarity")
        qid = hub.ins("INSERT INTO questions(task, asker, requester, text, asked) VALUES(?,?,?,?,?)",
                      (task, "dev", "manager", "Strip the seller's branding on import, or keep it?\nOption 1 is faster.",
                       hub.now()))
        self.raise_item(question_id=f"Q-{qid}", also=self.ANOTHER,
                        details="The lead's proposal, as written:\n> **Strip the seller's branding** on import, or "
                                "keep it? Option 1 is faster.\n\nI agree with option 1.")
        self.assertEqual(self.item(3)["details"].count("branding"), 1)
        self.assertNotIn("in its own words", self.item(3)["details"])
        # the asker's codes (RULES.md, "People read words, not codes"; on 25 November 2026, 42 of 85 question cards of a
        # fleet quoted them): a code that the question can mean is words, and every other code stays as it is written
        t0, first = hub.now(), hub.q1("SELECT question FROM needs WHERE id=1")["question"]
        for goal, title in ((5, "Grow the shop"), (20, "Another goal")):
            hub.q("INSERT INTO goals(id, title, text, state, revision, limits, created, updated, request_id) "
                  "VALUES(?,?,'The long words of the goal','active',1,'{}',?,?,?)", (goal, title, t0, t0, f"g{goal}"))
        hub.q("UPDATE tasks SET goal_id=5 WHERE id=?", (task,))
        later = hub.ins("INSERT INTO tasks(title, owner, requester, state, created, follows) VALUES(?,?,?,?,?,?)",
                        ("Fix the *weekly* report", "dev", "manager", "working", t0, task))
        narrowed = hub.ins("INSERT INTO tasks(title, owner, requester, state, created, follows, scope_person) "
                           "VALUES(?,?,?,?,?,?,?)",
                           ("Refund a person's order", "dev", "manager", "working", t0, task, 7))
        hub.q("INSERT INTO tasks(id, title, owner, requester, state, created) VALUES(800,'Other work','ops','manager',"
              "'working',?)", (t0,))
        hub.q("INSERT INTO needs(id, title, why, todo, raised, by) VALUES(340,'Road works','W','P',?,'manager')", (t0,))
        duty = hub.ins("INSERT INTO responsibilities(agent, text, state, revision, created, updated, created_by, "
                       "request_id) VALUES('dev','Answer the late invoices. Then more words.','active',1,?,?,"
                       "'manager','d1')", (t0, t0))
        hub.q("INSERT INTO duty_cases(id, responsibility, key, title, source, state, opened, by) "
              "VALUES(3,?,'k','Late invoice of a shop','check','open',?,'dev')", (duty, t0))
        for item, agent in ((7, "dev"), (95, "ops")):
            hub.q("INSERT INTO standing(id, agent, scope, kind, words, author_kind, author, created) "
                  "VALUES(?,?,'all','instruction',?,'owner','owner',?)",
                  (item, agent, "Each grant is a card\nfor the owner", t0))
        for event, recipient in ((40102, "dev"), (30, "manager")):
            hub.q("INSERT INTO ui_requests(request_id, kind, text, event_id, created, client, recipient) "
                  "VALUES(?,'message','Use the cheaper plan',?,?,'mac',?)", (f"m{event}", event, t0, recipient))
        hub.q("INSERT INTO agent_messages(id, sender, recipient, text, created, request_id) "
              "VALUES(14,'dev','manager','x',?,'a14')", (t0,))
        hub.q("INSERT INTO prompts(id, task, agent, tool, input, key, created) VALUES(9,?,'dev','Bash','x','k',?)",
              (task, t0))
        hub.q("INSERT INTO reports(id, from_agent, to_agent, kind, text, severity, delivered, created, request_id) "
              "VALUES(3,'dev','manager','risk','x','low','yes',?,'u3')", (t0,))
        hub.q("INSERT INTO owner_reports(id, text, about, created, agent) VALUES(4,'x','',?,'dev')", (t0,))
        private, long = (hub.ins("INSERT INTO questions(task, asker, requester, text, asked) VALUES(?,?,?,?,?)",
                                 (on, "dev", "manager", words, t0))
                         for on, words in ((narrowed, "Refund it?"),
                                           (task, "Which export do I keep for the shop, the old one or the new one?\n"
                                                  "The new one is faster and cheaper.")))

        def quoted(text, **extra):
            """The details of the card of a new question of dev's with these words, and the question's row."""
            qid = hub.ins("INSERT INTO questions(task, asker, requester, text, asked) VALUES(?,?,?,?,?)",
                          (task, "dev", "manager", text, hub.now()))
            self.raise_item(question_id=f"Q-{qid}", also=self.ANOTHER, **extra)
            return (self.item(hub.q1("SELECT MAX(id) n FROM needs")["n"])["details"],
                    hub.q1("SELECT text FROM questions WHERE id=?", (qid,))["text"])

        # bugs (the validation of 26 November 2026, M1, S2 and S3): the hub names a row that the question cannot mean,
        # as words that look like codes (a road, a model, a tax id) or a task, a card, a goal, a standing item or an
        # owner's message of other work; "C-3PO" loses its start; a code in a web address, an email address, code or
        # a code block changes; a bare C-<n> names a case (a conversation counts from 1 too); or the manager, which
        # reads the card too, reads the words of a narrowed pair's task or question
        kept = (f"Is the T-800 figure right? Carretera N-340, km 12. The G-20 summit, off the M-30; can I take I-95? "
                f"Tax id G-28123456, case C-3, C-3PO, version T-{later}.5. See https://shop.example.com/edit?task="
                f"T-{later}, `T-{later}`, `outputs/T-{later}/report.md`, T-{later}@example.com, "
                f"outputs/T-{later}/plan.md, outputs/T-{later}, T-{narrowed} and Q-{private}.\n- T-99: failed\n"
                f"Step:\n```\ncat T-{later}\n```")
        self.assertEqual(quoted(kept)[0], f"Dev's question, in its own words:\n\"{kept}\"")
        # bugs: a code stays where the question means a thing of its own work; a thing has another thing's words (a
        # goal its long words, not its title); a name keeps its line break or a Markdown mark, or is longer than 70
        # characters; a question's words read as a statement with no "the question" before them; a code of a kind
        # with no name leaves a hole, or a kind word comes after the noun that says it ("the report a report")
        asked = (f"Can I merge T-{task} after T-{later}? Q-{first} and Q-{long} asked it, N-1 waits, and N-340 is "
                 f"another card. It is for G-5 and R-{duty}/C-3 of R-{duty}, per I-7 and M-40102 (AM-14, P-9, UP-3, "
                 f"OR-4), and the report UP-3 is old.")
        details, row = quoted(asked)
        self.assertEqual(details, "Dev's question, in its own words: \"Can I merge “Survey” after “Fix the weekly "
                                  "report”? The question “I need read on the repository.” and the question “Which "
                                  "export do I keep for the shop, the old one or the new one? Th...” asked it, “Which "
                                  "name?” waits, and N-340 is another card. It is for “Grow the shop” and “Late "
                                  "invoice of a shop” of “Answer the late invoices”, per “Each grant is a card for the "
                                  "owner” "
                                  "and “Use the cheaper plan” (an agent's message, a permission request, a report, a "
                                  "message to you), and the report is old.\"")
        # bug: the asker's own row loses its codes, which the agents and the tools read
        self.assertEqual(row, asked)
        # bug: details that quote the question with the hub's words get a second copy of it (the validation, S4)
        self.assertEqual(quoted(f"Is T-{later} done?", details="Dev asks: is “Fix the weekly report” done?")[0],
                         "Dev asks: is “Fix the weekly report” done?")

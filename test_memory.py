"""An agent's own memory (owner direction, 19 October 2026; AUTONOMY.md P7, 27 October 2026): remember, recall,
forget, the start block and the review, and the knowledge file an agent writes itself. In-process hub, a temporary
database and a set clock; for the knowledge write, temporary Git repositories in the shape the fleet runs
(test_config_ref.py). No AI calls.

Memory is current: it holds the lessons that are true now. remember first answers with the closest lessons the agent
already holds, and the agent decides; a removed lesson leaves every start and every search of memory and stays in the
history; a session starts with every lesson that matches its work inside one bound of characters; and a review lists
the lessons that the work contradicted, and no clock adds one (decision 39). The rows of earlier rounds stay readable.
"""
import datetime
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import uuid
from unittest.mock import patch
from zoneinfo import ZoneInfo

import hub
from test_ui_api import OwnerAPI

MADRID = ZoneInfo("Europe/Madrid")
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "mac-studio": "127.0.0.4"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]},
                   "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio", "can": ["shell"]}},
        "goals": {"timezone": "Europe/Madrid", "review_hour": 9, "sweep_minutes": 15}}
LESSON = ("The deploy check of acme/web is `npm run smoke`, not the CI job called deploy: that job passes while the "
          "smoke is skipped. The script itself is in the repository, in package.json.")
PREVENTS = "Reading the CI job name and deploying a build whose smoke never ran."
# LESSON said again in other words: most of its words are in it, so remember holds it and asks.
AGAIN = "For acme/web the deploy check is npm run smoke; the CI job called deploy passes with the smoke skipped."
DAY = 86400

PROFILE = """# Profile: vps

Written by the owner. Agents cannot change it.

**Character.** Careful.

**Responsible for.** The machines and the services they reach.

**May do without asking.** Read files.

**Must ask first.** Spending.

**Knowledge files.**
- knowledge/services.md
- knowledge/suppliers.md
"""


def git(*args, cwd=None):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def at(text, zone=MADRID):
    return datetime.datetime.fromisoformat(text).replace(tzinfo=zone).timestamp()


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for cls in (Writing, Reading, Removal, Closest, CloseFromWork, Keeping, Evidence, Review, Dream, OldRows, Migration,
                StartText, KnowledgeWrite, Shown, NotesBase, NotesAtStart, Outside):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Base(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(TEAM))
        self.clock = at("2026-10-19T14:20")
        clock = patch.object(hub, "now", lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.task = self.new_task()

    def new_task(self, owner="vps", title="Fix the acme/web deploy", details="The smoke fails for the customer"):
        return hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt) "
                       "VALUES(?,?,?,?,?,?,'running',?,1)",
                       (title, details, "the smoke is green", "none", owner, "manager", hub.now()))

    def tool(self, who, name, task=None, **args):
        """One tool call of an agent, in the session of its own task."""
        if hub.role_of(who) == "manager":
            return hub.call_tool(who, name, args)
        tid = task if task is not None else self.task
        args = dict(args, task_id=hub.tref(tid))
        return hub.call_tool(who, name, args, ("test-generation", hub.tref(tid), 1))

    def ok(self, who, name, task=None, **args):
        text, error = self.tool(who, name, task=task, **args)
        self.assertFalse(error, text)
        return text

    def refused(self, who, name, task=None, **args):
        text, error = self.tool(who, name, task=task, **args)
        self.assertTrue(error, text)
        return text

    def remember(self, who="vps", about="acme/web", text=LESSON, prevents=PREVENTS, task=None, **more):
        return self.ok(who, "remember", task=task, request_id=str(uuid.uuid4()), about=about, text=text,
                       prevents=prevents, **more)

    def lessons(self, n, about="acme/web", words="the deploy step", who="vps", task=None):
        """n lessons of one tag that say much the same, written beside each other on purpose (new=true)."""
        return [self.remember(who=who, about=about, text=f"Lesson {k} on {words}: number {k}.",
                              prevents=f"Mistake {k}.", task=task, new=True) for k in range(n)]

    def duty(self, agent="vps"):
        with hub.LOCK:
            return hub.duty_save(hub.duty_fields(
                {"agent": agent, "text": "Keep the shop's nightly deploy working. When it fails, find out why, fix "
                                         "it and tell the owner. Any refund you ask me first.", "watch": []}, True),
                "manager", hub.now())

    def keyed(self, r, key="deploy-2026-10-19", agent="vps",
              text="The deploy fails when the lock file is stale; delete it before the build.",
              prevents=f"R-1 opening a case with the key 'deploy-2026-10-19' again", about="the shop"):
        """One lesson as the work writes it when a case of a duty is delivered: with that case's duty and key."""
        with hub.LOCK, hub.transaction():
            return hub.memory_from_work(agent, text, prevents, about, hub.now(), task=self.task,
                                        responsibility=r["id"], prevents_key=key)

    def show(self, *memory_ids, task=None, attempt=9):
        """A later start of a task showed these lessons whole: the rows that memory_shown_rows writes at a start."""
        for m in memory_ids:
            hub.q("INSERT OR IGNORE INTO memory_shown(memory,task,attempt,at) VALUES(?,?,?,?)",
                  (m, task or self.task, attempt, self.clock))

    def contradict(self, r, key="deploy-2026-10-19", when=None, shown=True):
        """The key comes back: by default after a later start showed every lesson that claimed it, which is when the
        hub counts it against them (memory_contradicted)."""
        if shown:
            self.show(*[m["id"] for m in hub.q("SELECT id FROM memories WHERE responsibility=? AND prevents_key=? "
                                               "AND dropped IS NULL", (r["id"], key))])
        with hub.LOCK, hub.transaction():           # every lesson that claimed the key, whoever wrote it
            return hub.memory_contradicted(r["id"], key, when if when is not None else self.clock)

    def row(self, memory_id=None):
        return hub.q1("SELECT * FROM memories WHERE id=?", (memory_id,)) if memory_id else \
            hub.q1("SELECT * FROM memories ORDER BY id DESC LIMIT 1")

    def count(self, where="1=1"):
        return hub.q1(f"SELECT COUNT(*) n FROM memories WHERE {where}")["n"]

    def block(self, task=None):
        """The memory part of the task's start block (AUTONOMY.md 6.4, slot 4)."""
        return hub.memory_start_text("vps", task or self.task)

    def shown(self, text):
        return [x for x in text.split("\n") if x.startswith("- M-")]

    def review(self, agent="vps"):
        with hub.LOCK:
            hub.duty_reviews(self.clock)
        last = hub.duty_review_last(agent)
        return hub.q1("SELECT * FROM tasks WHERE id=?", (last["task"],)) if last.get("task") else None

    def finish(self, task):
        hub.q("UPDATE tasks SET state='completed', outcome='completed', delivered=? WHERE id=?",
              (self.clock, task["id"]))

    def reviews(self, agent="vps"):
        return hub.q1("SELECT COUNT(*) n FROM tasks WHERE owner=? AND title IN (?,?)",
                      (agent, hub.MEMORY_REVIEW_TASK["title"], hub.DUTY_REVIEW_TASK["title"]))["n"]


class Writing(Base):
    def test_a_lesson_is_stored_with_its_tag_its_task_and_what_it_prevents(self):
        said = self.remember()
        m = self.row()
        self.assertEqual((m["agent"], m["about"], m["text"], m["prevents"]), ("vps", "acme/web", LESSON, PREVENTS))
        self.assertEqual((m["by_task"], m["created"], m["recalls"], m["dropped"]), (self.task, self.clock, 0, None))
        self.assertEqual((m["kind"], m["reinforced"], m["folded_into"], m["archived"]), ("lesson", 0, None, None))
        self.assertIn("M-1 is yours", said)
        # The answer says where the next session reads it, which is the whole point of writing it.
        self.assertIn("A task whose words name this tag or the lesson's own words starts with it", said)
        self.assertIn('recall with about="acme/web"', said)

    def test_what_it_prevents_is_required_because_a_lesson_must_be_falsifiable(self):
        for missing in ({"prevents": ""}, {"prevents": " "}, {"prevents": "x\ny"}):
            said = self.refused("vps", "remember", request_id=str(uuid.uuid4()), about="acme/web", text=LESSON,
                                **missing)
            self.assertIn("prevents", said)
            self.assertIn("cannot be shown to be wrong", said)
        self.assertEqual(self.count(), 0)

    def test_the_tag_is_the_agents_own_short_words(self):
        self.assertIn("about must be one short tag", self.refused(
            "vps", "remember", request_id=str(uuid.uuid4()), about="x" * 61, text=LESSON, prevents=PREVENTS))
        self.remember(about="  the   fleet ")
        self.assertEqual(self.row()["about"], "the fleet")       # one line of its own words, whitespace collapsed

    def test_the_lesson_has_a_length_and_may_hold_more_than_one_line(self):
        self.assertIn("text must be 1 to 1200", self.refused(
            "vps", "remember", request_id=str(uuid.uuid4()), about="acme/web", text="x" * 1201, prevents=PREVENTS))
        self.remember(text="One.\nTwo.")
        self.assertEqual(self.row()["text"], "One.\nTwo.")

    def test_a_login_is_never_a_memory(self):
        login = "bws://" + str(uuid.uuid4())
        hub.register_fingerprints(login, [{"kind": "password", "hash": "a" * 64, "len": 12}])
        with patch.object(hub, "secret_hit", lambda *texts: any("hunter2hunter2" in str(t) for t in texts)):
            said = self.refused("vps", "remember", request_id=str(uuid.uuid4()), about="acme/web",
                                text="The password is hunter2hunter2.", prevents=PREVENTS)
        self.assertIn("contains a login", said)
        self.assertEqual(self.count(), 0)

    def test_a_login_registered_after_the_write_never_rides_a_start_text(self):
        """guard refuses a login that is registered at the moment of the write, and mask_secrets replaces the ones
        known then — but the owner registers a login whenever he adds one, so a key written in the clear last week
        is only caught on the way out."""
        self.remember(text="The API key is hunter2hunter2 and it works.", prevents="Looking it up again.")
        with patch.object(hub, "secret_hit", lambda *x: any("hunter2hunter2" in str(one) for one in x)), \
             patch.object(hub, "secret_spans", lambda text: [(text.index("hunter2hunter2"),
                                                              text.index("hunter2hunter2") + 14)]
                          if "hunter2hunter2" in text else []):
            self.assertNotIn("hunter2hunter2", hub.start_text("vps", self.task))
            self.assertIn(hub.MASK, hub.start_text("vps", self.task))
            self.assertNotIn("hunter2hunter2", self.ok("vps", "recall"))
            self.assertNotIn("hunter2hunter2", self.ok("vps", "recall", memory="M-1"))
            self.assertNotIn("hunter2hunter2", self.ok("vps", "recall", search="works"))
            # and in the answer that shows the close lessons before a write
            close = self.remember(text="The API key works for the build too.", prevents="Again.")
            self.assertIn("Nothing is written yet", close)
            self.assertIn(hub.MASK, close)
            self.assertNotIn("hunter2hunter2", close)

    def test_masking_on_the_shelf_commits_nothing_of_a_half_written_task(self):
        """secret_key reached the registered logins with hub.q, which commits — and masking is on the start-text
        path, which admit_task calls inside the transaction that writes a task, its attempt and its start event
        together or not at all."""
        self.remember()

        class FailAt:
            def __init__(self, db):
                self.db = db

            def execute(self, sql, *args):
                if sql.startswith("INSERT INTO events("):
                    raise RuntimeError("disk I/O error")
                return self.db.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(self.db, name)

        before = [hub.q1(f"SELECT COUNT(*) n FROM {x}")["n"] for x in ("tasks", "attempts", "events")]
        with patch.object(hub, "DB", FailAt(hub.DB)):
            with self.assertRaises(RuntimeError):
                with hub.LOCK, hub.transaction():
                    hub.admit_task("manager", {"owner": "vps", "title": "Another acme/web task", "details": "d",
                                               "done_when": "w", "needs": "none", "goal": None, "goal_id": None,
                                               "parent": None, "follows": None, "case_id": None, "why": None})
        self.assertFalse(hub.DB.in_transaction)
        self.assertEqual([hub.q1(f"SELECT COUNT(*) n FROM {x}")["n"] for x in ("tasks", "attempts", "events")],
                         before)

    def test_the_line_says_how_much_outside_text_the_writing_task_had_read(self):
        """The hub's own observation and not the agent's, which is the whole of its value: the attack is "this check
        is unreliable, skip it", inside authority the agent already holds, so no refusal ever fires."""
        for n in range(3):
            hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,?,?,1,?,'{}',1,'')",
                    (self.clock, "vps", self.task, "gmail_read"))
        hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,?,?,1,?,'{}',1,'')",
                (self.clock, "vps", self.task, "message_agent"))
        hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,?,?,1,?,'{}',1,'')",
                (self.clock, "vps", self.task, "report_progress"))        # not a read of outside text
        self.remember()
        self.assertEqual(self.row(1)["read_untrusted"], 4)
        said = f"in {hub.tref(self.task)}, with 4 reads of outside text behind it"
        self.assertIn(said, hub.start_text("vps", self.task))
        self.assertIn(said, self.ok("vps", "recall"))
        self.assertIn(said, self.ok("vps", "recall", memory="M-1"))
        # a task that read nothing from outside says only where it was written
        other = self.new_task(owner="studio")
        self.remember(who="studio", task=other)
        self.assertIn(f"(in {hub.tref(other)})", self.ok("studio", "recall", task=other))

    def test_the_same_request_id_writes_one_memory_and_gives_its_answer_again(self):
        rid = str(uuid.uuid4())
        first = self.ok("vps", "remember", request_id=rid, about="acme/web", text=LESSON, prevents=PREVENTS)
        again = self.ok("vps", "remember", request_id=rid, about="acme/web", text=LESSON, prevents=PREVENTS)
        self.assertEqual(first, again)
        self.assertEqual(self.count(), 1)
        self.assertIn("already used for another call", self.refused(
            "vps", "remember", request_id=rid, about="acme/web", text="Another lesson.", prevents=PREVENTS))

    def test_the_manager_keeps_memories_of_its_own(self):
        self.ok("manager", "remember", request_id=str(uuid.uuid4()), about="the owner",
                text="He wants the number first and the reason after it.", prevents="A preamble he has to read past.")
        self.assertEqual(self.row()["agent"], "manager")
        self.assertIn("the owner", self.ok("manager", "recall"))

    def test_the_fields_of_earlier_rounds_are_refused_by_the_hub_and_nothing_is_written(self):
        """held, covers, kind, cost_minutes and recheck left the tool (AUTONOMY.md P7). A session that started before
        the release still holds the old list, so its call is refused in the hub's own words, with nothing written."""
        self.remember()
        for extra in ({"held": "M-1"}, {"covers": ["M-1"]}, {"kind": "dead_end"}, {"cost_minutes": 30},
                      {"recheck": "Run it again."}):
            said = self.refused("vps", "remember", request_id=str(uuid.uuid4()), about="stripe",
                                text="A refund over 50 EUR answers 402.", prevents="A wrong reading.", **extra)
            self.assertIn(f"remember does not take {next(iter(extra))}", said)
            self.assertIn("nothing happened", said)
        for extra in ({"covers": "M-1"}, {"forgotten": True}, {"stale": True}):
            self.assertIn(f"recall does not take {next(iter(extra))}", self.refused("vps", "recall", **extra))
        for name in ("deliver_result", "close_case"):
            schema = next(t for t in hub.tools_for("vps") if t["name"] == name)["inputSchema"]["properties"]
            self.assertTrue({"cost_minutes", "recheck"}.isdisjoint(schema), name)
            self.assertIn("tried", schema)
        self.assertEqual(self.count(), 1)


class Reading(Base):
    def setUp(self):
        super().setUp()
        self.remember(about="acme/web")
        self.remember(about="the owner", text="He wants the number first.", prevents="A preamble.")
        self.remember(about="stripe", text="A refund over 50 EUR answers 402 with the test key.",
                      prevents="Reading a 402 as a network fault.")

    def test_the_default_is_one_page_and_says_what_else_there_is(self):
        said = self.ok("vps", "recall")
        self.assertIn("3 lessons of yours, the newest first:", said)
        for ref in ("M-1", "M-2", "M-3"):
            self.assertIn(ref, said)
        self.assertIn('Your tags: "acme/web" (1), "stripe" (1), "the owner" (1).', said)
        self.assertIn('recall memory="M-<id>" gives one whole', said)

    def test_no_shape_puts_the_store_into_a_session_and_page_reaches_the_rest(self):
        with patch.object(hub, "MEMORY_SHOWN", 2):
            first = self.ok("vps", "recall")
            self.assertIn("M-3", first)
            self.assertIn("M-2", first)
            self.assertNotIn("M-1", first)
            self.assertIn("(page 1 of 2, 3 in all. page=2 for the next one", first)
            second = self.ok("vps", "recall", page=2)
            self.assertIn("M-1", second)
            self.assertNotIn("M-3", second)
            # a page past the end gives the last one rather than nothing
            self.assertIn("page 2 of 2", self.ok("vps", "recall", page=99))
        self.assertIn("page is a whole number from 1.", self.refused("vps", "recall", page="x"))

    def test_the_tags_line_is_capped_because_a_store_reaches_thousands(self):
        for n in range(4, 30):
            self.remember(about=f"tag{n:02d}", text=f"Lesson {n}.", prevents=f"Mistake {n}.")
        said = self.ok("vps", "recall")
        self.assertIn("and 9 more tags", said)                  # 29 tags, 20 named
        self.assertEqual(len([x for x in said.split("\n") if x.startswith("  Your tags:")]), 1)
        self.assertLess(len(next(x for x in said.split("\n") if "Your tags:" in x)), 700)

    def test_one_tag_on_its_own(self):
        said = self.ok("vps", "recall", about="stripe")
        self.assertIn('1 lesson of yours about "stripe", the newest first:', said)
        self.assertIn("M-3", said)
        self.assertNotIn("M-1", said)
        self.assertIn("M-3", self.ok("vps", "recall", about="Stripe"))       # one tag, whatever its case

    def test_a_tag_with_nothing_under_it_names_the_tags_there_are(self):
        said = self.ok("vps", "recall", about="shopify")
        self.assertIn('No lesson of yours is about "shopify"', said)
        self.assertIn('"acme/web"', said)

    def test_one_memory_in_full_says_where_it_was_written_and_how_often_it_was_read(self):
        self.ok("vps", "recall")                        # the list counts as a read
        said = self.ok("vps", "recall", memory="M-1")
        self.assertIn("M-1 [acme/web] written 2026-10-19 14:20", said)
        self.assertIn(f"in {hub.tref(self.task)}", said)
        self.assertIn("read 2 times, last 2026-10-19 14:20", said)
        self.assertIn("Expected to change or prevent: " + PREVENTS, said)

    def test_a_search_reaches_the_tag_the_lesson_and_what_it_prevents(self):
        self.assertIn("M-1", self.ok("vps", "recall", search="package.json"))        # the lesson
        self.assertIn("M-3", self.ok("vps", "recall", search="stripe"))              # the tag
        self.assertIn("M-2", self.ok("vps", "recall", search="preamble"))            # what it prevents
        self.assertIn('No lesson of yours has "nothing at all"', self.ok("vps", "recall", search="nothing at all"))
        self.assertIn("search_history finds", self.ok("vps", "recall", search="nothing at all"))
        self.assertIn("Search for at least two characters.", self.refused("vps", "recall", search="x"))

    def test_a_search_of_several_words_wants_all_of_them(self):
        """FTS5 juxtaposition is AND, which is what "lesson 1337" means. With OR the commonest word in the query
        brings back the newest page of everything and the lesson that was asked for is not in it — measured at
        5,000 lessons, where it found nothing it was asked for."""
        for n in range(30):
            self.remember(about="numbered", text=f"Lesson {n}: a detail.", prevents=f"Mistake {n}.", new=True)
        said = self.ok("vps", "recall", search="Lesson 17")
        self.assertIn("Lesson 17: a detail.", said)
        self.assertIn("1 lesson of yours", said)
        self.assertNotIn("Lesson 29", said)

    def test_the_search_answers_the_same_without_fts5_on_the_machine(self):
        """A machine whose sqlite3 lacks the module pays a linear read and gets the same answer. It must not be a
        refused schema step: build_schema's refusals are what a release reads."""
        for n in range(4):
            self.remember(about="numbered", text=f"Lesson {n}: a detail.", prevents=f"Mistake {n}.", new=True)
        with patch.object(hub, "MEMORY_FTS", [False]):
            said = self.ok("vps", "recall", search="package.json")
            self.assertIn("M-1", said)
            self.assertIn("Lesson 2: a detail.", self.ok("vps", "recall", search="Lesson 2"))
        self.assertEqual(hub.build_schema(), [])

    def test_since_limits_a_list_to_what_was_written_after_a_date(self):
        self.clock += 40 * DAY
        self.remember(about="later", text="A lesson of November.", prevents="A November mistake.")
        said = self.ok("vps", "recall", since="2026-11-01")
        self.assertIn("M-4", said)
        self.assertNotIn("M-1", said)
        self.assertIn("since is an ISO date", self.refused("vps", "recall", since="the other day"))

    def test_full_gives_a_page_whole_instead_of_shortened(self):
        short = self.ok("vps", "recall")
        self.assertNotIn("Expected to change or prevent", short)
        self.assertIn("Expected to change or prevent: " + PREVENTS, self.ok("vps", "recall", full=True))

    def test_the_first_shape_given_wins_so_one_call_answers_one_question(self):
        said = self.ok("vps", "recall", memory="M-1", about="stripe", search="preamble")
        self.assertIn("Expected to change or prevent", said)
        self.assertNotIn("M-3", said)

    def test_a_memory_is_one_agents_own_and_no_other_agent_reads_it(self):
        self.assertIn("is not your memory", self.refused("manager", "recall", memory="M-1"))
        self.assertIn("is not your memory", self.refused("studio", "recall", memory="M-1",
                                                         task=self.new_task(owner="studio")))
        self.assertFalse(hub.memory_read_allowed("manager", self.row(1)))
        self.assertTrue(hub.memory_read_allowed("vps", self.row(1)))
        self.assertIn("You have no lessons yet", self.ok("studio", "recall", task=self.new_task(owner="studio")))

    def test_an_agents_notes_are_its_own_too_and_the_manager_reads_neither(self):
        """The reason in memory_read_allowed's docstring applies to the notes word for word, so the manager branch
        that see_notes had is closed (owner direction, 19 October 2026)."""
        with hub.LOCK, hub.transaction():
            hub.notes_save("vps", "I run the repository's own check before the smoke.", "what the work taught me",
                           "vps", self.clock, task=self.task)
        said, error = self.tool("manager", "see_notes", agent="vps")
        self.assertTrue(error, said)
        self.assertIn("not even the manager", said)
        self.assertIn("repository's own check", self.ok("vps", "see_notes"))

    def test_an_unknown_memory_says_so(self):
        self.assertIn("There is no memory M-9", self.refused("vps", "recall", memory="M-9"))
        self.assertIn("not a memory id", self.refused("vps", "recall", memory="nine"))

    def test_recall_only_reads(self):
        self.assertTrue(next(t for t in hub.tools_for("vps") if t["name"] == "recall")["annotations"]["readOnlyHint"])
        self.assertIn("recall", hub.CHAT_TOOLS)


class Removal(Base):
    """AUTONOMY.md P7: a lesson that is contradicted or no longer true is removed. It leaves every start and every
    search of memory, the history keeps it, and its row stays (phase 1) in the columns every release already hides."""

    def setUp(self):
        super().setUp()
        self.remember()
        self.reason = "The CI job runs the smoke since 18 October, so the lesson sends me the long way."

    def forget(self, **args):
        return self.ok("vps", "forget", request_id=str(uuid.uuid4()), memory="M-1", reason=self.reason, **args)

    def test_a_removed_lesson_leaves_every_start_and_every_search_of_memory(self):
        self.assertIn("M-1", self.block())
        said = self.forget()
        self.assertIn("M-1 is removed: no start and no recall shows it again", said)
        self.assertIn("Your history keeps it", said)
        self.assertNotIn("M-1", self.block())
        self.assertIn("You have written no memories yet.", hub.start_text("vps", self.task))
        self.assertIn("You have no lessons yet", self.ok("vps", "recall"))
        self.assertIn("You have no lessons yet", self.ok("vps", "recall", every=True))
        self.assertNotIn("M-1", self.ok("vps", "recall", search="package.json"))
        self.assertNotIn("M-1", self.ok("vps", "recall", about="acme/web"))
        self.assertNotIn("M-1", self.ok("vps", "recall", contradicted=True))
        with patch.object(hub, "MEMORY_FTS", [False]):              # the scan hides it too
            self.assertNotIn("M-1", self.ok("vps", "recall", search="package.json"))
        self.assertEqual(hub.memory_view("vps")["lessons"], [])      # and the owner's page of what stands
        # reading it by its id says where it went, and not what it said
        whole = self.ok("vps", "recall", memory="M-1")
        self.assertIn("M-1 was removed 2026-10-19 14:20 CEST by vps: The CI job runs the smoke", whole)
        self.assertIn("the long way. A removed lesson", whole)
        self.assertIn('read_history with ref="M-1"', whole)
        self.assertNotIn("package.json", whole)

    def test_the_row_stays_in_the_columns_an_older_release_already_hides(self):
        self.forget()
        m = self.row(1)
        self.assertEqual((m["dropped"], m["dropped_by"], m["drop_reason"], m["text"]),
                         (self.clock, "vps", self.reason, LESSON))
        self.assertEqual(self.count(), 1)

    def test_the_history_keeps_the_lesson_and_its_removal(self):
        """P6 keeps every old event, so the memory can hold current lessons only: the lesson as written and its
        removal with the reason are two records of the agent's history, found by its search and opened by its ref."""
        self.forget()
        found = self.ok("vps", "search_history", query="smoke long way")
        self.assertIn("M-1 forgotten by vps: The CI job runs the smoke", found)
        opened = self.ok("vps", "read_history", ref="M-1")
        self.assertIn("package.json", opened)                       # what it said
        self.assertIn("forgotten by vps", opened)                   # and why it went
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE ref='M-1' AND agent='vps' AND text LIKE "
                                "'%forgotten by%'")["n"], 1)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM history WHERE ref='M-1' AND agent<>'vps'")["n"], 0)

    def test_the_reason_is_required_because_the_history_keeps_it(self):
        for missing in ({}, {"reason": ""}, {"reason": "x\ny"}):
            said = self.refused("vps", "forget", request_id=str(uuid.uuid4()), memory="M-1", **missing)
            self.assertIn("reason", said)
        self.assertIsNone(self.row(1)["dropped"])

    def test_only_its_own_agent_removes_it(self):
        self.assertIn("Only its own agent removes it", self.refused(
            "manager", "forget", request_id=str(uuid.uuid4()), memory="M-1", reason="not mine"))
        self.assertIsNone(self.row(1)["dropped"])

    def test_removing_it_twice_says_who_removed_it_and_why(self):
        self.forget()
        said = self.refused("vps", "forget", request_id=str(uuid.uuid4()), memory="M-1", reason="Wrong again.")
        self.assertIn("was already removed", said)
        self.assertIn("18 October", said)

    def test_the_same_request_id_gives_its_answer_again(self):
        rid = str(uuid.uuid4())
        first = self.ok("vps", "forget", request_id=rid, memory="M-1", reason="Wrong since 18 October.")
        self.assertEqual(first, self.ok("vps", "forget", request_id=rid, memory="M-1",
                                        reason="Wrong since 18 October."))
        self.assertEqual(self.count("dropped IS NOT NULL"), 1)

    def test_a_removed_lesson_cannot_be_written_again_in_its_place(self):
        self.forget()
        said = self.refused("vps", "remember", request_id=str(uuid.uuid4()), about="acme/web", text=AGAIN,
                            prevents=PREVENTS, instead_of="M-1")
        self.assertIn("M-1 is already removed", said)
        self.assertIn("Write the lesson without instead_of", said)


class Closest(Base):
    """AUTONOMY.md P7: remember answers with the closest lessons the agent already holds, found by a text search, and
    the agent decides -- the same lesson again, a replacement, or a new one."""

    def setUp(self):
        super().setUp()
        self.remember()

    def test_remember_answers_with_the_closest_lessons_and_writes_nothing(self):
        said = self.remember(text=AGAIN)
        self.assertIn("Nothing is written yet: you already hold a lesson close to this one:", said)
        self.assertIn("- M-1 [acme/web] The deploy check of acme/web is `npm run smoke`", said)
        self.assertIn("(written 2026-10-19)", said)
        self.assertIn('call remember again with instead_of="M-<id>"', said)
        self.assertIn("call remember again with new=true", said)
        self.assertEqual(self.count(), 1)
        # no answer is kept for that request_id: nothing was written, so nothing is to be repeated
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM tool_commands WHERE tool='remember'")["n"], 1)

    def test_the_call_that_decides_may_use_the_same_request_id(self):
        rid = str(uuid.uuid4())
        args = dict(about="acme/web", text=AGAIN, prevents=PREVENTS)
        self.assertIn("Nothing is written yet", self.ok("vps", "remember", request_id=rid, **args))
        said = self.ok("vps", "remember", request_id=rid, new=True, **args)
        self.assertIn("M-2 is yours", said)
        self.assertEqual(said, self.ok("vps", "remember", request_id=rid, new=True, **args))     # and repeats it
        self.assertEqual(self.count(), 2)

    def test_the_same_lesson_again_stands_in_its_place_dated_today(self):
        """A lesson whose words the agent's own work changed: the agent writes it again, and it is current."""
        self.clock += 30 * DAY
        said = self.remember(text=LESSON, instead_of="M-1")
        self.assertIn("M-2 is yours", said)
        self.assertIn("M-1 is removed, naming this one", said)
        self.assertIn("Nothing can contradict this one, because it names no case key: only your own work can show it "
                      "wrong.", said)
        old, new = self.row(1), self.row(2)
        self.assertEqual((old["dropped"], old["drop_reason"]), (self.clock, "written again as M-2"))
        self.assertEqual((new["text"], new["created"], new["dropped"]), (LESSON, self.clock, None))

    def test_a_replacement_takes_the_place_and_the_claim_of_the_old_one(self):
        r = self.duty()
        keyed = self.keyed(r)
        said = self.remember(about="the shop", text="The lock file is a symptom: the cache volume fills up first.",
                             prevents="The deploy failing the same way.", instead_of=hub.mref(keyed))
        self.assertIn(f"It takes over what {hub.mref(keyed)} claimed", said)
        new = self.row()
        self.assertEqual((new["responsibility"], new["prevents_key"]), (r["id"], "deploy-2026-10-19"))
        self.assertIsNotNone(self.row(keyed)["dropped"])

    def test_a_different_lesson_is_written_beside_them_with_new(self):
        said = self.remember(text=AGAIN, new=True)
        self.assertIn("M-2 is yours", said)
        self.assertEqual(self.count("dropped IS NULL"), 2)

    def test_a_related_lesson_that_is_not_close_is_written_at_once(self):
        """The same tag and a word or two in common is related, not close: a hold there would cost a call for every
        lesson about a product the agent works on."""
        said = self.remember(text="acme/web builds need Node 20; the image of the build box has 18.",
                             prevents="A build that fails on the box.")
        self.assertIn("M-2 is yours", said)
        self.assertEqual(hub.memory_closest("vps", "acme/web", "The deploy of acme/web runs on Fridays."), [])
        # two words in common are not enough: these say different things about the deploy's smoke
        self.assertIn("M-3 is yours", self.remember(about="postgres", prevents="A red smoke that is the pool.",
                                                    text="The smoke of the deploy needs the postgres pool at 20."))

    def test_the_closest_come_first_and_never_more_than_three(self):
        for words in ("npm run smoke is the deploy check of acme/web, not the CI job",
                      "the CI job called deploy passes while the smoke of acme/web is skipped",
                      "acme/web: the smoke script is in package.json in the repository",
                      "deploy acme/web only after npm run smoke"):
            self.remember(text=words, new=True)
        said = self.remember(text=LESSON + " Always.")
        self.assertIn("you already hold 3 lessons close to this one", said)
        lines = [x for x in said.split("\n") if x.startswith("- M-")]
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[0].startswith("- M-1 "), lines)            # the one that says it in the same words

    def test_only_the_agents_own_current_lessons_are_close(self):
        other = self.new_task(owner="studio")
        self.assertIn("M-2 is yours", self.remember(who="studio", task=other, text=AGAIN))   # vps's are not studio's
        self.ok("vps", "forget", request_id=str(uuid.uuid4()), memory="M-1", reason="Wrong since 18 October.")
        self.assertIn("M-3 is yours", self.remember(text=AGAIN))         # and a removed one is close to nothing

    def test_without_fts5_the_close_ones_are_found_too(self):
        with patch.object(hub, "MEMORY_FTS", [False]):
            self.assertIn("Nothing is written yet", self.remember(text=AGAIN))
        self.assertEqual(self.count(), 1)

    def test_instead_of_and_new_are_two_different_decisions(self):
        said = self.refused("vps", "remember", request_id=str(uuid.uuid4()), about="acme/web", text=AGAIN,
                            prevents=PREVENTS, instead_of="M-1", new=True)
        self.assertIn("Give one or the other.", said)
        self.assertIn("not yours", self.refused("studio", "remember", request_id=str(uuid.uuid4()), about="x",
                                                text=AGAIN, prevents=PREVENTS, instead_of="M-1",
                                                task=self.new_task(owner="studio")))

    def test_the_words_a_search_of_lessons_matches_on(self):
        self.assertEqual(hub.memory_terms("The deploy of acme/web is done with npm, and the deploy again."),
                         ["deploy", "acme", "web", "npm"])
        self.assertEqual(len(hub.memory_terms(" ".join(f"word{n}" for n in range(100)))), hub.MEMORY_TERMS)
        self.assertEqual(hub.memory_overlap("one two three", "four five six"), (0.0, 0))
        self.assertEqual(hub.memory_overlap(LESSON, LESSON)[0], 1.0)
        self.assertGreaterEqual(hub.memory_overlap(AGAIN, LESSON, ("acme/web",))[0], 0.5)
        # the words of the tags make two lessons related and not close
        related = "The deploy of acme/web runs on Fridays."
        self.assertGreaterEqual(hub.memory_overlap(related, LESSON)[0], 0.5)
        self.assertEqual(hub.memory_overlap(related, LESSON, ("acme/web",)), (0.0, 1))
        # two shared words make two lessons close only when they are all that the shorter one says
        self.assertEqual(hub.memory_overlap("The smoke of the deploy needs the pool.", LESSON), (0.0, 2))
        self.assertEqual(hub.memory_overlap("Pin node.", "Node 20 is needed for builds; pin it in .nvmrc."), (1.0, 2))
        self.assertEqual(hub.memory_overlap("Use npm run smoke.", LESSON), (0.75, 3))


class CloseFromWork(Base):
    """AUTONOMY.md P7, as a review of the build found: learned and tried write their lesson at the end of a task, where
    nobody is left to decide, so a lesson close to one the agent holds is written all the same, and the pair goes to
    the agent's next review -- by their ids and the reason, never their words."""

    def setUp(self):
        super().setUp()
        self.remember()                                             # M-1: LESSON

    def deliver(self, task=None, **lesson):
        return self.ok("vps", "deliver_result", task=task, outcome="completed", what_was_done="Fixed the deploy",
                       where_output_is="commit a95cee6", how_checked="The smoke is green", **lesson)

    def test_a_lesson_close_to_one_held_is_written_and_the_pair_kept(self):
        said = self.deliver(learned=AGAIN, prevents=PREVENTS)
        self.assertIn("M-2 keeps what you learned", said)
        self.assertEqual(self.count("dropped IS NULL"), 2)          # nothing is lost at the end of a task
        self.assertEqual(self.row(2)["text"], AGAIN)
        self.assertEqual(hub.memory_close_pairs("vps"), [(1, 2)])
        self.assertEqual(json.loads(hub.kv_get("memory_close:vps")), [[1, 2]])     # test_release_turns.later_data
        self.assertEqual(hub.memory_reviewers(), ["vps"])

    def test_the_next_review_lists_the_pair_by_ids_and_never_their_words(self):
        self.deliver(learned=AGAIN, prevents=PREVENTS)
        t = self.review()
        self.assertEqual((t["title"], t["owner"]), (hub.MEMORY_REVIEW_TASK["title"], "vps"))
        self.assertIn("The lessons of yours that this review lists:\nM-1 and M-2 say much the same: keep one, and "
                      "forget the other.", t["details"])
        self.assertIn("Two that say much the same thing: keep one and forget the other", t["details"])
        self.assertIn('memory="M-<id>" for one', t["details"])
        for words in ("npm run smoke", "smoke skipped", PREVENTS):  # its requester reads the task too
            self.assertNotIn(words, t["details"])
        self.assertEqual(hub.duty_review_last("vps")["lessons"], ["M-1+M-2"])

    def test_tried_is_checked_too_and_the_words_the_hub_puts_before_it_count_for_nothing(self):
        said = self.deliver(tried="The CI job called deploy is no check of acme/web: it passes with npm run smoke "
                                  "skipped. Check: the job's log says skipped.")
        self.assertIn("M-2 keeps what did not work", said)
        self.assertEqual(hub.memory_close_pairs("vps"), [(1, 2)])
        # "What did not work: " is the hub's: two lessons that share it and two words more are not close
        self.assertEqual(hub.memory_overlap(hub.MEMORY_TRIED + "The cache volume was full.",
                                            hub.MEMORY_TRIED + "The cache volume of the runner."), (0.0, 2))

    def test_the_lessons_of_one_delivery_make_no_pair_with_each_other(self):
        """learned and tried of one call are written side by side on purpose, as remember new=true writes them."""
        said = self.deliver(learned="Check the pool before the logs.", prevents="Twenty minutes in the logs.",
                            tried="Reading the logs before the pool cost twenty minutes. Check: the pool count.")
        self.assertIn("M-3 keeps what did not work", said)
        self.assertGreaterEqual(hub.memory_overlap(self.row(2)["text"], self.row(3)["text"])[0], 0.5)
        self.assertEqual(hub.memory_close_pairs("vps"), [])
        self.assertIsNone(self.review())

    def test_a_lesson_not_close_makes_no_pair_and_no_review(self):
        self.deliver(learned="A refund over 50 EUR answers 402 with the Stripe test key.", prevents="A wrong reading.")
        self.assertEqual(self.count(), 2)
        self.assertIsNone(hub.kv_get(hub.MEMORY_CLOSE_KEY + "vps"))
        self.assertEqual(hub.memory_reviewers(), [])
        self.assertIsNone(self.review())

    def test_a_case_lesson_close_to_one_held_keeps_its_key_and_its_pair(self):
        """close_case writes through the same function, with the case's duty and key."""
        keyed = self.keyed(self.duty(), text=AGAIN, about="acme/web")
        self.assertEqual(hub.memory_close_pairs("vps"), [(1, keyed)])
        self.assertEqual(self.row(keyed)["prevents_key"], "deploy-2026-10-19")

    def test_a_pair_one_of_whose_lessons_is_removed_leaves_the_review(self):
        self.deliver(learned=AGAIN, prevents=PREVENTS)
        self.ok("vps", "forget", task=self.new_task(), request_id=str(uuid.uuid4()), memory="M-2",
                reason="The same as M-1.")
        self.assertEqual(hub.memory_close_pairs("vps"), [])
        self.assertEqual(hub.memory_reviewers(), [])
        self.assertIsNone(self.review())

    def test_a_pair_one_of_whose_lessons_is_written_again_leaves_the_review(self):
        """Two that say different things after all: one of them written again in words that say how."""
        self.deliver(learned=AGAIN, prevents=PREVENTS)
        self.remember(task=self.new_task(), instead_of="M-2",
                      text="For acme/web the smoke runs on Fridays only; the CI job called deploy runs on each push.")
        self.assertIsNotNone(self.row(2)["dropped"])
        self.assertEqual(hub.memory_close_pairs("vps"), [])
        self.assertIsNone(self.review())

    def test_a_pair_listed_and_kept_starts_no_second_review_and_a_new_pair_does(self):
        self.deliver(learned=AGAIN, prevents=PREVENTS)
        t = self.review()
        self.finish(t)
        self.assertEqual(self.review()["id"], t["id"])              # kept as it was: no second review by itself
        self.deliver(task=self.new_task(), prevents=PREVENTS,
                     learned="npm run smoke is the deploy check of acme/web; the CI job called deploy passes with "
                             "the smoke skipped.")
        second = self.review()
        self.assertNotEqual(second["id"], t["id"])
        self.assertIn("M-1 and M-2 say much the same", second["details"])     # it still needs looking at
        self.assertIn("M-1 and M-3 say much the same", second["details"])
        self.assertEqual(self.reviews(), 2)

    def test_the_manager_reads_the_pair_in_its_review_message(self):
        self.ok("manager", "remember", request_id=str(uuid.uuid4()), about="acme/web", text=LESSON, prevents=PREVENTS)
        with hub.LOCK, hub.transaction():
            hub.memory_from_work("manager", AGAIN, PREVENTS, "acme/web", self.clock)
        with hub.LOCK:
            hub.duty_reviews(self.clock)
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id DESC LIMIT 1")["text"]
        self.assertIn("[hub] Lessons of yours need looking at:\nM-2 and M-3 say much the same", said)
        self.assertNotIn("npm run smoke", said)

    def test_without_fts5_the_pair_is_found_too(self):
        with patch.object(hub, "MEMORY_FTS", [False]):
            self.deliver(learned=AGAIN, prevents=PREVENTS)
        self.assertEqual(hub.memory_close_pairs("vps"), [(1, 2)])

    def test_the_kept_pairs_are_bounded_and_a_broken_record_reads_as_none(self):
        self.lessons(4)                                             # M-2 to M-5, side by side on purpose
        with patch.object(hub, "MEMORY_MOST", 2), hub.LOCK, hub.transaction():
            hub.memory_close_rows("vps", [(2, 3), (2, 4), (3, 5)])
        self.assertEqual(hub.memory_close_pairs("vps"), [(2, 4), (3, 5)])     # the newest
        for broken in ("not json", json.dumps({"a": 1}), json.dumps([[1, 99], [1], "x", [1, True], [1.0, 2]])):
            hub.kv_set(hub.MEMORY_CLOSE_KEY + "vps", broken)
            self.assertEqual(hub.memory_close_pairs("vps"), [], broken)
            self.assertEqual(hub.memory_reviewers(), [], broken)


class Keeping(Base):
    def test_nothing_in_this_feature_deletes_a_row(self):
        """Phase 1 of AUTONOMY.md P7 keeps the row of a removed lesson: a purge is a later choice."""
        import re as _re
        source = open(hub.__file__).read()
        # inside a string literal, so the comment that says there is none does not count as one
        self.assertEqual(_re.findall(r"[\"']\s*DELETE\s+FROM\s+memor\w*", source, _re.I), [])
        self.assertNotIn("MEMORY_KEEP", source)

    def test_the_hub_removes_nothing_by_itself(self):
        """No sweep archives, folds or removes a lesson: a contradicted one and an old one go to the agent's review,
        which decides."""
        self.remember()
        r = self.duty()
        keyed = self.keyed(r)
        self.contradict(r)
        self.clock += 5 * 365 * DAY
        hub.tick()
        self.assertEqual(self.count("dropped IS NULL AND archived IS NULL AND folded_into IS NULL"), 2)
        self.assertFalse(hasattr(hub, "memory_sweep"))
        self.assertIsNone(self.row(keyed)["dropped"])


class Evidence(Base):
    """What the fleet knows about a lesson. The work writes a lesson when it ends and marks it contradicted when its
    case key comes back (memory_from_work, memory_contradicted); a lesson with no key can never be contradicted, and
    only the agent's own work shows it wrong (AUTONOMY.md decision 39)."""

    def test_no_clock_marks_a_lesson_however_old(self):
        """AUTONOMY.md decision 39 (the owner, 28 October 2026: "are we not over engineering?"): no age rule. A lesson
        goes to the review only when the work contradicts it; the agent removes or rewrites one itself."""
        self.remember()                                             # by hand: no key
        keyed = self.keyed(self.duty())
        self.clock += 10 * 365 * DAY
        self.assertEqual(hub.memory_to_review("vps"), [])
        self.assertEqual(hub.memory_reviewers(), [])
        for said in (self.ok("vps", "recall"), self.ok("vps", "recall", memory="M-1"),
                     self.ok("vps", "recall", memory=hub.mref(keyed)), self.block()):
            for word in ("confirm", "stale", "days"):
                self.assertNotIn(word, said.replace("lock file is stale", ""))
        self.assertNotIn("memory.review_days", hub.SETTINGS)
        self.assertEqual({"stale", "held_until"} & set(hub.memory_view("vps")["lessons"][0]), set())

    def test_a_repeat_of_a_rewrite_replays_its_answer_instead_of_refusing(self):
        """A repeat of the same write with the same request_id is the documented way back from an answer that was
        lost. The first call of a rewrite removes the lesson it replaced, so a check before agent_write would refuse
        every repeat — and an agent told "already removed" writes the lesson again on its own, keyless, losing the
        claim that this path exists to carry."""
        r = self.duty()
        first = self.keyed(r)
        rid = str(uuid.uuid4())
        args = dict(about="the shop", instead_of=hub.mref(first), text="The lock file is a symptom.",
                    prevents="The deploy failing the same way.")
        said = self.ok("vps", "remember", request_id=rid, **args)
        self.assertEqual(said, self.ok("vps", "remember", request_id=rid, **args))
        self.assertEqual(self.count("dropped IS NULL"), 1)
        # the claim reached the one lesson that stands, and only it
        new = hub.q1("SELECT * FROM memories WHERE dropped IS NULL")
        self.assertEqual((new["responsibility"], new["prevents_key"]), (r["id"], "deploy-2026-10-19"))
        self.assertEqual(self.contradict(r), [hub.mref(new["id"])])
        # a new request_id for a lesson already removed still says so, with what replaced it
        said = self.refused("vps", "remember", request_id=str(uuid.uuid4()), **args)
        self.assertIn(f"already removed (written again as {hub.mref(new['id'])})", said)

    def test_the_duty_and_the_key_are_one_claim_and_travel_together(self):
        r = self.duty()
        for half in (dict(responsibility=r["id"], prevents_key=None), dict(responsibility=None, prevents_key="k")):
            with self.assertRaises(hub.ToolError) as caught:
                with hub.LOCK, hub.transaction():
                    hub.memory_from_work("vps", "A lesson.", "A mistake.", "the shop", self.clock, task=self.task,
                                         **half)
            self.assertIn("both the duty and its key, or neither", str(caught.exception))
        self.assertEqual(self.count(), 0)

    def test_recall_contradicted_gives_what_the_work_contradicted_and_nothing_else(self):
        self.assertIn("No lesson of yours is contradicted", self.ok("vps", "recall", contradicted=True))
        self.remember()
        r = self.duty()
        keyed = self.keyed(r)
        self.contradict(r)
        self.clock += 10 * 365 * DAY
        said = self.ok("vps", "recall", contradicted=True)
        # the contradicted one only: the keyless one is not listed however old it is
        self.assertIn("1 contradicted lesson of yours, the most contradicted first:", said)
        self.assertIn(f"  {hub.mref(keyed)} [the shop]", said)
        self.assertNotIn("  M-1 [", said)
        self.assertIn('remember instead_of="M-<id>"', said)
        self.assertIn("The hub removes nothing by itself", said)
        # the default answer counts them and sends a session there instead of carrying them
        self.assertIn("1 of yours is contradicted: recall contradicted=true.", self.ok("vps", "recall"))

    def test_every_line_and_every_full_reading_say_what_the_fleet_counted(self):
        r = self.duty()
        keyed = self.keyed(r)
        self.contradict(r)
        self.contradict(r, when=self.clock + 60)
        said = self.ok("vps", "recall")
        self.assertIn("CONTRADICTED 2×", said)
        self.assertIn(f"claims to stop R-{r['id']}/'deploy-2026-10-19'", said)
        full = self.ok("vps", "recall", memory=hub.mref(keyed))
        self.assertIn("That key HAS come back 2 times since", full)
        self.assertIn(f'Write it again with remember instead_of="{hub.mref(keyed)}" so it says which', full)
        # and a contradicted lesson still stands: counting is the hub's, deciding is the agent's
        self.assertIsNone(self.row(keyed)["dropped"])

    def test_a_keyless_lesson_in_full_says_that_only_the_work_shows_it_wrong(self):
        self.remember()
        self.clock += 10 * 365 * DAY
        said = self.ok("vps", "recall", memory="M-1")
        self.assertIn("Nothing can contradict this one: it came out of an ordinary task and names no case key, so only "
                      "your own work can show it wrong.", said)
        self.assertNotIn("your review lists it", said)
        # memory phase 2: what the outside-read count sees is said where a lesson is read whole, not in RULES.md
        self.assertIn(hub.MEMORY_OUTSIDE_SAID, said)

    def test_remembers_own_words_carry_the_rule_that_an_instruction_is_not_a_memory(self):
        said = next(x["description"] for x in hub.tools_for("vps") if x["name"] == "remember")
        self.assertIn(hub.NOTES_RULE, said)
        self.assertIn('instead_of="M-<id>"', said)
        self.assertIn("new=true", said)
        self.assertIn("Say how you know it.", said)
        self.assertLess(len(said), 1400)                      # P9.3: the description is short now (2,350 before)

    def test_phase_2_asks_how_you_know_with_no_failure_only_framing(self):
        """Memory phase 2 (AUTONOMY.md decision 43): a model told to record only failures gained less from its memory,
        and the ones that gained most wrote how they knew each rule. What only RULES.md said is said by the tools."""
        tools = {x["name"]: x for x in hub.tools_for("vps")}
        deliver = tools["deliver_result"]
        for gone in ("nothing will ask again", "the same hours", "wasted hours"):
            self.assertNotIn(gone, deliver["description"])
        self.assertIn("how you know it", deliver["description"])
        self.assertIn("how you know it", deliver["inputSchema"]["properties"]["learned"]["description"])
        self.assertIn("how you know it", tools["close_case"]["inputSchema"]["properties"]["learned"]["description"])
        for name in ("read_knowledge", "search_knowledge"):
            self.assertIn(hub.KNOWLEDGE_WORDS, tools[name]["description"])
        self.assertIn("No clock and no rule of the hub removes a lesson", tools["forget"]["description"])
        rules = (Path(__file__).resolve().parent / "RULES.md").read_text(encoding="utf-8")
        self.assertNotIn("What worked you would probably find again", rules)
        memory = rules[rules.index("## Your memory"):rules.index("## Where work goes")]
        self.assertLess(len(memory), 2000)                                  # about 10,000 before
        for tool in ("write_notes", "remember", "learned", "tried", "write_skill", "write_knowledge", "forget"):
            self.assertIn(f"`{tool}`", memory)


class Review(Base):
    """AUTONOMY.md P7, review on news: when the work contradicts a lesson of an agent's, its next review lists it, and
    the agent removes or rewrites it. Any agent, with a duty or without one. No clock starts one (decision 39)."""

    def keyed_again(self, r, key="deploy-2026-10-20", agent="vps"):
        """A second keyed lesson, of another key and other words, so it is no close pair of the first."""
        return self.keyed(r, key=key, agent=agent, text="Refunds over 50 EUR need the owner's yes first.",
                          prevents=f"R-{r['id']} opening a case with the key '{key}' again")

    def test_an_agent_without_a_duty_gets_a_review_of_its_contradicted_lessons_and_none_for_age(self):
        self.remember()
        self.clock += 10 * 365 * DAY
        self.assertIsNone(self.review())                            # no clock starts one (decision 39)
        r = self.duty(agent="studio")                               # vps worked a case of a duty it does not hold
        keyed = self.keyed(r)
        self.contradict(r)
        t = self.review()
        self.assertEqual((t["title"], t["owner"], t["requester"]), (hub.MEMORY_REVIEW_TASK["title"], "vps",
                                                                    "manager"))
        self.assertIn(f"The lessons of yours that this review lists:\n{hub.mref(keyed)}: contradicted 1×",
                      t["details"])
        self.assertNotIn("M-1:", t["details"])
        self.assertIn('call recall to read them: memory="m-<id>" for one, contradicted=true', t["details"].lower())
        self.assertIn('remember instead_of="M-<id>"', t["details"])
        self.assertIn("forget", t["details"])
        self.assertIn("without their words", t["details"])
        # its requester reads the task too, so it carries the ids and never the lessons' words
        self.assertNotIn("lock file", t["details"])
        self.assertIsNone(self.row(keyed)["dropped"])               # and the hub removes nothing

    def test_a_contradicted_lesson_starts_a_review_and_a_new_contradiction_another(self):
        r = self.duty(agent="studio")                               # vps worked a case of a duty it does not hold
        keyed = self.keyed(r)
        self.assertIsNone(self.review())
        self.contradict(r)
        t = self.review()
        self.assertIn(f"{hub.mref(keyed)}: contradicted 1×, last 2026-10-19 14:20", t["details"])
        self.finish(t)
        self.assertEqual(self.review()["id"], t["id"])               # the same lessons start no second review
        self.assertEqual(self.reviews(), 1)
        self.clock += 3600
        self.contradict(r)
        second = self.review()
        self.assertNotEqual(second["id"], t["id"])
        self.assertIn(f"{hub.mref(keyed)}: contradicted 2×", second["details"])

    def test_no_second_review_while_one_is_open_and_none_for_what_it_already_listed(self):
        r = self.duty(agent="studio")
        first = self.keyed(r)
        self.contradict(r)
        t = self.review()
        second = self.keyed_again(r)
        self.contradict(r, key="deploy-2026-10-20")
        self.review()
        self.assertEqual(self.reviews(), 1)                          # the first one is still open
        self.finish(t)
        again = self.review()                                       # the second is news; the first was listed and kept
        self.assertEqual(self.reviews(), 2)
        self.assertIn(f"{hub.mref(second)}: contradicted 1×", again["details"])
        self.assertIn(f"{hub.mref(first)}: contradicted 1×", again["details"])     # it still needs looking at
        self.finish(again)
        self.review()
        self.assertEqual(self.reviews(), 2)

    def test_a_lesson_written_again_or_removed_leaves_the_review(self):
        r = self.duty(agent="studio")
        first, second = self.keyed(r), self.keyed_again(r)
        self.contradict(r)
        self.contradict(r, key="deploy-2026-10-20")
        self.assertEqual([m["id"] for m in hub.memory_to_review("vps")], [first, second])
        self.remember(about="the shop", text="The cache volume fills up first; the lock file is only a symptom.",
                      prevents="The deploy failing the same way.", instead_of=hub.mref(first))
        self.assertEqual(self.row()["prevents_key"], "deploy-2026-10-19")     # the claim goes on, uncontradicted
        self.ok("vps", "forget", request_id=str(uuid.uuid4()), memory=hub.mref(second), reason="The owner changed it.")
        self.assertEqual(hub.memory_to_review("vps"), [])

    def test_a_duty_holders_review_lists_its_lessons_with_its_duties(self):
        self.duty()                                                 # news: a new duty, from the manager
        r = self.duty(agent="studio")
        keyed = self.keyed(r)
        self.contradict(r)
        t = self.review()
        self.assertEqual(t["title"], hub.DUTY_REVIEW_TASK["title"])
        self.assertIn("This review started because your duties have news", t["details"])
        self.assertIn(f"{hub.mref(keyed)}: contradicted 1×", t["details"])
        self.assertIn("every lesson listed below has been written again or removed", t["done_when"])

    def test_the_manager_reads_its_review_as_a_message(self):
        r = self.duty(agent="studio")
        keyed = self.keyed(r, agent="manager")                      # the manager closed a case of studio's duty
        self.contradict(r)
        with hub.LOCK:
            hub.duty_reviews(self.clock)
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' AND text LIKE '%Lessons of yours%' "
                      "ORDER BY id DESC LIMIT 1")["text"]
        self.assertIn(f"[hub] Lessons of yours need looking at:\n{hub.mref(keyed)}: contradicted 1×", said)
        self.assertNotIn("lock file", said)
        self.assertNotIn("Your duties have news", said)



class Dream(Base):
    """Memory phase 3 (AUTONOMY.md decision 44): the review is the agent's own dream. It also starts on a count of the
    events of its own work since its last review -- never on a clock -- and every review carries what the hub's own
    records say since the last one that ended well, with ids and never a lesson's words."""

    def setUp(self):
        super().setUp()
        hub.kv_set(hub.MEMORY_COUNT_FROM, "0")                    # migrate seeded the real now: the count from 0
        every = patch.object(hub, "MEMORY_COUNT_EVERY", 0)       # counted on every sweep, unless a test says
        every.start()
        self.addCleanup(every.stop)
        hub.MEMORY_COUNTED.clear()
        self.addCleanup(hub.MEMORY_COUNTED.clear)

    def ended(self, title, details="The deploy step failed again", **columns):
        """A task of vps that has ended, with the columns that say how."""
        cols = dict({"state": "completed", "outcome": "completed", "delivered": self.clock}, **columns)
        tid = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt) "
                      "VALUES(?,?,?,?,?,?,?,?,1)", (title, details, "done", "none", "vps", "manager", cols["state"],
                                                    self.clock))
        hub.q(f"UPDATE tasks SET {', '.join(f'{k}=?' for k in cols)} WHERE id=?", (*cols.values(), tid))
        return tid

    def records(self, task):
        return task["details"].split("What the hub's records say since your last review:\n")[1]

    def new_listed(self, task):
        """The lessons that a review names as written since its records start, in its order."""
        line = next(x for x in self.records(task).split("\n") if x.startswith("Lessons that your work wrote"))
        return line.split(": ", 1)[1].split(". ")[0].split(" and ")[0].split(", ")

    def test_ten_new_lessons_start_a_review_and_nine_do_not(self):
        self.lessons(9)
        self.assertIsNone(self.review())
        self.clock += 60
        self.lessons(1, words="the release step")
        t = self.review()
        self.assertEqual((t["title"], t["owner"], t["requester"]), (hub.MEMORY_REVIEW_TASK["title"], "vps",
                                                                    "manager"))
        self.assertIn("needed doing again 10 times since its last review", t["why"])
        self.assertEqual(self.new_listed(t), [f"M-{n}" for n in range(10, 0, -1)])     # the newest first
        self.assertIn(hub.MEMORY_DREAM_WHAT, t["details"])
        self.assertNotIn("Lesson 0 on", t["details"])               # its requester reads it: ids, never the words
        self.assertIn("checked against those records", t["done_when"])
        self.assertEqual(hub.duty_review_last("vps")["dreamed"], 0)
        self.assertEqual(self.reviews(), 1)

    def test_tasks_that_needed_doing_again_count_and_name_what_their_start_showed(self):
        mine = self.lessons(6)                                      # M-1..M-6, on the deploy step
        self.lessons(1, about="stripe", words="refunds")            # M-7: no word of the deploy
        failed = self.ended("Fix the deploy step", state="failed", outcome="failed")
        self.show(1, 2, 7, task=failed)                             # its start showed these whole
        refused = self.ended("Write the report", accepted=0, checked_at=self.clock)
        second = self.ended("Check the backups", attempt=2, restarts=1)      # a reminder or a limit: not rework
        followed = self.ended("Ship the release")
        fix = self.new_task(title="Ship the release again")
        hub.q("UPDATE tasks SET follows=? WHERE id=?", (followed, fix))
        self.remember(about="releases", text="The release needs the tag pushed before the build.",
                      prevents="A build of the old tag.", task=followed)          # M-8, in a task that needed rework
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (followed,))
        review = self.ended(hub.MEMORY_REVIEW_TASK["title"], state="failed")  # a review counts for nothing
        clean = self.ended("Answer the customer")                   # a clean one neither
        self.assertTrue(all(mine))
        self.assertEqual(len(hub.memory_rework_tasks("vps", 0)), 3)
        t = self.review()                                           # 8 lessons and 3 tasks: 11
        said = self.records(t)
        self.assertIn(f"{hub.tref(followed)} needed doing again ({hub.tref(fix)} follows it); it wrote M-8.", said)
        self.assertIn(f"{hub.tref(refused)} needed doing again (refused by its requester); it wrote no lesson.", said)
        for absent in (second, review, clean):
            self.assertNotIn(hub.tref(absent) + " ", said)
        line = next(x for x in said.split("\n") if x.startswith(hub.tref(failed) + " "))
        self.assertTrue(line.startswith(f"{hub.tref(failed)} needed doing again (failed); its start showed M-"), line)
        self.assertNotIn("M-7", line)                               # shown beside the cause, not matched by it
        self.assertTrue(line.endswith("; it wrote no lesson."), line)
        self.assertNotIn("tag pushed", t["details"])

    def test_a_canceled_review_keeps_its_records_and_is_not_started_again_at_once(self):
        self.lessons(10)
        first = self.review()
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (first["id"],))
        self.clock += 60
        self.assertEqual(self.review()["id"], first["id"])          # nothing new since it started
        self.lessons(10, words="the release step")                  # M-11..M-20
        second = self.review()
        self.assertNotEqual(second["id"], first["id"])
        self.assertIn("M-1", self.new_listed(second))               # the canceled one's records are not lost
        self.assertEqual(hub.duty_review_last("vps")["dreamed"], 0)
        self.finish(second)
        self.clock += 60
        self.lessons(12, words="the backup step", task=second["id"])  # written in a review: not counted
        self.assertEqual(self.review()["id"], second["id"])
        self.lessons(10, words="the cache step")                    # M-33..M-42
        third = self.review()
        self.assertNotEqual(third["id"], second["id"])
        listed = self.new_listed(third)
        self.assertNotIn("M-1", listed)                             # the window moved with the review that ended well
        self.assertNotIn("M-21", listed)                            # and what the review wrote is not its record
        self.assertEqual((listed[0], listed[-1]), ("M-42", "M-33"))  # M-21..M-32 were written in the review
        self.assertEqual(hub.duty_review_last("vps")["dreamed"], second["created"])

    def test_the_hub_counts_what_a_review_did_and_decides_nothing(self):
        self.lessons(10)
        t = self.review()
        self.remember(text="The deploy step needs the cache warmed first; seen in three runs.",
                      prevents="A cold deploy.", instead_of="M-1", task=t["id"])
        self.ok("vps", "forget", task=t["id"], request_id=str(uuid.uuid4()), memory="M-2",
                reason="The owner changed the deploy.")
        self.ok("vps", "search_history", task=t["id"], query="deploy step")
        self.finish(t)
        self.clock += 60
        self.review()
        done = hub.duty_review_last("vps")["done"]
        self.assertEqual({k: done[k] for k in ("state", "new", "again", "removed", "records", "standing")},
                         {"state": "completed", "new": 0, "again": 1, "removed": 1, "records": 1, "standing": 9})
        said = hub.q1("SELECT what FROM log WHERE what LIKE 'review of vps (%' ORDER BY id DESC LIMIT 1")["what"]
        self.assertIn(f"review of vps ({hub.tref(t['id'])}, completed) did: 0 new lesson(s), 1 written again, 1 removed",
                      said)
        self.review()
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM log WHERE what LIKE 'review of vps (%'")["n"], 1)   # once
        self.assertEqual(self.count("dropped IS NULL"), 9)          # and the hub removed nothing itself

    def test_only_lessons_that_stand_count_and_the_count_starts_at_the_release(self):
        self.lessons(10)
        self.ok("vps", "forget", request_id=str(uuid.uuid4()), memory="M-3", reason="It was wrong.")
        self.assertIsNone(self.review())                            # nine stand: nothing to review is no review
        hub.kv_set(hub.MEMORY_COUNT_FROM, str(self.clock))         # the release came after all of them
        self.clock += 1
        self.lessons(9, words="the release step")
        self.assertIsNone(self.review())
        self.clock += 60
        self.lessons(1, words="the cache step")
        listed = self.new_listed(self.review())
        self.assertEqual((listed[0], listed[-3:]), ("M-20", ["M-4", "M-2", "M-1"]))     # M-3 was removed

    def test_a_key_that_keeps_coming_back_counts_the_case_before_it_once(self):
        r = self.duty()
        cases = []
        for n in range(10):
            cases.append(hub.ins("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,repeated) "
                                 "VALUES(?,?,?,?,?,?,?,?)", (r["id"], "disk-full", "Disk full", "watch", "closed",
                                                             self.clock - 1000 + n, "vps", int(n > 0))))
            tid = self.ended(f"Handle the disk {n}")
            hub.q("UPDATE tasks SET duty_case=?, responsibility=? WHERE id=?", (cases[-1], r["id"], tid))
        self.clock += 60
        hub.ins("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,repeated) "
                "VALUES(?,?,?,?,?,?,?,?)", (r["id"], "disk-full", "Disk full", "watch", "open", self.clock, "vps", 1))
        back = hub.memory_rework_tasks("vps", self.clock - 1)
        self.assertEqual([why for _, why in back], ["its case's key came back"])
        self.assertEqual(back[0][0]["duty_case"], cases[-1])        # the case just before it, and only that one

    def test_the_manager_is_never_reviewed_by_the_count(self):
        self.lessons(12, who="manager")
        with hub.LOCK:
            hub.duty_reviews(self.clock)
        self.assertEqual(hub.duty_review_last("manager"), {})
        self.assertIsNone(hub.q1("SELECT 1 FROM events WHERE agent='manager' AND kind='say' AND text LIKE "
                                 "'%records say%'"))
        r = self.duty(agent="studio")                               # news for the manager: a contradicted lesson
        self.keyed(r, agent="manager")
        self.contradict(r)
        with hub.LOCK:
            hub.duty_reviews(self.clock)
        said = hub.q1("SELECT text FROM events WHERE agent='manager' AND kind='say' AND text LIKE '%Lessons of yours%'")
        self.assertNotIn("records say", said["text"])               # a review by message carries no records

    def test_migrate_seeds_the_start_of_the_count_once_and_never_moves_it(self):
        hub.q("DELETE FROM kv WHERE k=?", (hub.MEMORY_COUNT_FROM,))
        self.assertEqual(hub.memory_count_from(), 0)
        self.assertEqual(hub.migrate(), [])
        self.assertEqual(hub.memory_count_from(), self.clock)
        self.clock += 3600
        hub.migrate()                                               # every later start of the hub
        self.assertEqual(hub.memory_count_from(), self.clock - 3600)

    def test_a_failed_duty_task_names_the_lesson_that_claims_its_key_first(self):
        r = self.duty()
        lessons = []
        for key, text in (("disk-full", "Clear the build cache when the disk is full."),
                          ("queue-1", "Restart the queue worker before the import."),
                          ("cert-1", "Renew the certificate a week early."),
                          ("backup-1", "Check the backup before the deploy.")):
            lessons.append(self.keyed(r, key=key, text=text,
                                      prevents=f"R-{r['id']} opening a case with the key '{key}' again"))
        case = hub.ins("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,repeated) "
                       "VALUES(?,?,?,?,?,?,?,?)", (r["id"], "disk-full", "Disk full", "watch", "closed", self.clock,
                                                   "vps", 0))
        failed = self.ended("Check the backup before the deploy", details="The backup check failed", state="failed",
                            outcome="failed")
        hub.q("UPDATE tasks SET duty_case=?, responsibility=? WHERE id=?", (case, r["id"], failed))
        self.show(*lessons, task=failed)                            # its start showed all four, the duty's own
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (failed,))
        # the one that claims its case's key, then the one its words match, though both are the duty's oldest
        self.assertEqual(hub.memory_implicated("vps", t), [lessons[0], lessons[3], lessons[2]])

    def test_an_agent_is_counted_at_most_every_ten_minutes(self):
        with patch.object(hub, "MEMORY_COUNT_EVERY", 600):
            self.assertIsNone(self.review())                        # counted now: nothing yet
            self.lessons(10)
            self.clock += 599
            self.assertIsNone(self.review())                        # not counted again yet
            self.clock += 1
            self.assertIsNotNone(self.review())


class OldRows(Base):
    """The rows of earlier rounds keep their data and stay readable (AUTONOMY.md P7): lessons that `held` bore out, a
    summary and the lessons it folded, an archived lesson, and a dead end with its cost and how to check it again.
    Written here as those rounds wrote them, by SQL, because no tool writes them any more."""

    def setUp(self):
        super().setUp()
        add = ("INSERT INTO memories(agent,about,text,prevents,created,by_task,request_id,reinforced,reinforced_at,"
               "folded_into,archived,kind,cost_minutes,recheck) VALUES('vps',?,?,?,?,?,?,?,?,?,?,?,?,?)")
        t0 = self.clock
        self.held = hub.ins(add, ("acme/web", "Run the smoke before the deploy of acme/web.", "A red deploy.", t0,
                                  self.task, "r1", 2, t0, None, None, "lesson", None, None))
        self.summary = hub.ins(add, ("the shop", "The deploy fails for one reason, the lock file.", "Three hunts.",
                                     t0, None, "r2", 0, None, None, None, "lesson", None, None))
        self.members = [hub.ins(add, ("the shop", f"Old lesson {n} about the shop's deploy.", "A hunt.", t0 - DAY,
                                      self.task, f"r3{n}", 0, None, self.summary, None, "lesson", None, None))
                        for n in range(2)]
        for member in self.members:
            hub.q("INSERT INTO memory_folds(summary,member,created,by) VALUES(?,?,?,'vps')",
                  (self.summary, member, t0))
        self.archived = hub.ins(add, ("the dashboard", "The old dashboard of acme/web is at /admin.", "A lost hour.",
                                      t0 - 400 * DAY, self.task, "r4", 0, None, None, t0, "lesson", None, None))
        self.wall = hub.ins(add, ("stripe", "A Stripe test key cannot refund a live charge.", hub.DEAD_END_PREVENTS,
                                  t0, self.task, "r5", 0, None, None, None, "dead_end", 180,
                                  "One refund with the test key: a 400 says the wall stands."))
        with hub.LOCK, hub.transaction():
            for mid in (self.held, self.summary, *self.members, self.archived, self.wall):
                hub.memory_indexed(mid)

    def test_each_one_reads_whole_by_its_id(self):
        said = self.ok("vps", "recall", memory=hub.mref(self.held))
        self.assertIn("The work bore it out 2 times, last 2026-10-19 14:20", said)
        said = self.ok("vps", "recall", memory=hub.mref(self.summary))
        self.assertIn(f"It is a summary of an earlier round, covering 2: {hub.mref(self.members[0])}, "
                      f"{hub.mref(self.members[1])}", said)
        said = self.ok("vps", "recall", memory=hub.mref(self.members[0]))
        self.assertIn("Old lesson 0 about the shop's deploy.", said)
        self.assertIn(f"since a summary of yours covered it in an earlier round, {hub.mref(self.summary)}", said)
        said = self.ok("vps", "recall", memory=hub.mref(self.archived))
        self.assertIn("Archived 2026-10-19 14:20 CEST in an earlier round", said)
        self.assertNotIn("your review lists it", said)          # the review reads what stands, only
        said = self.ok("vps", "recall", memory=hub.mref(self.wall))
        self.assertIn("DEAD END (3 h, written 2026-10-19):", said)
        self.assertIn("To find out cheaply whether it still holds: One refund with the test key", said)

    def test_the_lists_and_the_search_reach_them_as_before(self):
        default = self.ok("vps", "recall")
        for mid in (self.held, self.summary, self.wall):
            self.assertIn(hub.mref(mid), default)
        for mid in (*self.members, self.archived):
            self.assertNotIn(hub.mref(mid) + " ", default)
        self.assertIn("3 more, folded or archived in an earlier round, are not listed here", default)
        every = self.ok("vps", "recall", every=True)
        for mid in (self.held, self.summary, *self.members, self.archived, self.wall):
            self.assertIn(hub.mref(mid), every)
        self.assertIn(hub.mref(self.members[1]), self.ok("vps", "recall", search="Old lesson 1"))
        self.assertIn(hub.mref(self.archived), self.ok("vps", "recall", search="dashboard"))

    def test_the_owners_page_reads_them_with_every_field_it_had(self):
        lessons = {m["id"]: m for m in hub.memory_view("vps")["lessons"]}
        self.assertEqual(sorted(lessons), sorted([self.held, self.summary, self.wall]))
        self.assertEqual(lessons[self.held]["held"], 2)
        self.assertEqual(set(lessons[self.held]) & {"stale", "held_until"}, set())     # no clock (decision 39)
        self.assertEqual((lessons[self.wall]["kind"], lessons[self.wall]["cost_minutes"],
                          lessons[self.wall]["recheck"]),
                         ("dead_end", 180, "One refund with the test key: a 400 says the wall stands."))

    def test_a_dead_end_of_an_earlier_round_starts_a_task_that_names_it(self):
        task = self.new_task(title="Refund a stripe charge for a customer", details="")
        line = next(x for x in self.shown(self.block(task)) if x.startswith(f"- {hub.mref(self.wall)} "))
        self.assertIn("[stripe] DEAD END (3 h, written 2026-10-19): A Stripe test key cannot refund", line)
        self.assertIn("To check it again: One refund with the test key", line)
        self.assertNotIn('kind="dead_end"', line)
        self.clock += 10 * 365 * DAY                                # the same however old it is (decision 39)
        self.assertEqual(line, next(x for x in self.shown(self.block(task))
                                    if x.startswith(f"- {hub.mref(self.wall)} ")))
        self.assertIsNone(self.review())                           # and no clock starts a review for it

    def test_the_history_reads_them_too(self):
        self.assertIn("A Stripe test key cannot refund a live charge", self.ok("vps", "search_history",
                                                                              query="stripe refund"))
        self.assertIn("One refund with the test key", self.ok("vps", "read_history", ref=hub.mref(self.wall)))

    def test_one_of_them_written_again_is_an_ordinary_lesson_of_today(self):
        said = self.remember(about="stripe", text="Stripe refunds a live charge with a test key since May.",
                             prevents="Refusing to try what now works.", instead_of=hub.mref(self.wall))
        self.assertIn("is yours", said)
        new = self.row()
        self.assertEqual((new["kind"], new["cost_minutes"], new["recheck"], new["created"]),
                         ("lesson", None, None, self.clock))
        self.assertIsNotNone(self.row(self.wall)["dropped"])


class Migration(unittest.TestCase):
    """A database that took the memories table from the first push of this feature, before the columns the evidence
    needs. build_schema runs SCHEMA first and migrate after it, so anything that depends on a migrated column has to
    be in migrate: a step SCHEMA refuses is a step a release reports as refused (hub.check_schema)."""

    FIRST_PUSH = """CREATE TABLE memories(id INTEGER PRIMARY KEY, agent TEXT NOT NULL, about TEXT NOT NULL,
      text TEXT NOT NULL, prevents TEXT NOT NULL, created REAL NOT NULL, by_task INTEGER, request_id TEXT NOT NULL,
      recalls INTEGER NOT NULL DEFAULT 0, recalled REAL, dropped REAL, dropped_by TEXT, drop_reason TEXT);"""
    NEW = ("responsibility", "prevents_key", "contradicted", "contradicted_at", "reinforced", "reinforced_at",
           "read_untrusted", "folded_into", "archived", "kind", "cost_minutes", "recheck")

    def build(self, before=None):
        import sqlite3
        import tempfile
        tmp = tempfile.TemporaryDirectory(prefix="fleet-memory-migration-")
        self.addCleanup(tmp.cleanup)
        db = sqlite3.connect(tmp.name + "/test.db")
        db.row_factory = sqlite3.Row
        if before:
            db.executescript(before)
        old, hub.DB = hub.DB, db
        self.addCleanup(setattr, hub, "DB", old)
        return hub.build_schema()

    def columns(self):
        return {r["name"] for r in hub.q("PRAGMA table_info(memories)")}

    def indexes(self):
        return {r["name"] for r in hub.q("SELECT name FROM sqlite_master WHERE type='index'")}

    def test_a_fresh_database_refuses_no_step(self):
        self.assertEqual(self.build(), [])
        self.assertTrue(set(self.NEW) <= self.columns())
        self.assertIn("memory_claim", self.indexes())
        # AUTONOMY.md 6.1: removal uses the columns that exist, and adds none
        self.assertTrue({"dropped", "dropped_by", "drop_reason"} <= self.columns())
        self.assertFalse({"removed_at", "removed_why"} & self.columns())

    def test_the_table_of_the_first_push_is_migrated_and_refuses_no_step(self):
        self.assertEqual(self.build(self.FIRST_PUSH + "\nINSERT INTO memories(agent,about,text,prevents,created,"
                                                      "request_id) VALUES('vps','x','The old lesson.','z',1,'r');"),
                         [])
        self.assertTrue(set(self.NEW) <= self.columns())
        self.assertIn("memory_claim", self.indexes())
        # the lesson written before the columns existed still stands, and every count starts at zero
        m = hub.q1("SELECT * FROM memories WHERE id=1")
        self.assertEqual((m["text"], m["contradicted"], m["reinforced"], m["prevents_key"]),
                         ("The old lesson.", 0, 0, None))

    def test_the_search_index_is_probed_at_startup_and_is_never_a_refused_step(self):
        """A machine without FTS5 searches with a scan. If the probe were a schema step its refusal would be what
        hub.check_schema prints and a release reads, and that machine would fail every release it was offered. And
        the probe commits, so it belongs in migrate, which runs outside every transaction."""
        hub.MEMORY_FTS[0] = None
        self.assertEqual(self.build(), [])
        self.assertIsNotNone(hub.MEMORY_FTS[0])
        if hub.MEMORY_FTS[0]:
            self.assertIn("memory_fts", {r["name"] for r in hub.q("SELECT name FROM sqlite_master")})
        import sqlite3 as _sqlite3

        class NoFTS5:
            def __init__(self, db):
                self.db = db

            def execute(self, sql, *args):
                if "fts5" in sql:
                    raise _sqlite3.Error("no such module: fts5")
                return self.db.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(self.db, name)

        with patch.object(hub, "DB", NoFTS5(hub.DB)):
            self.assertFalse(hub.memory_search_probe())
        self.assertFalse(hub.MEMORY_FTS[0])
        hub.MEMORY_FTS[0] = None            # the next build probes again

    def test_the_search_index_is_born_non_empty_and_no_record_of_it_holds_a_secret(self):
        """FTS5 writes its config and one empty data block when the table is made, so every database has non-empty
        memory_fts_* tables from birth (test_site_mfa reads them)."""
        self.build()
        shadow = {r["name"] for r in hub.q("SELECT name FROM sqlite_master WHERE name LIKE 'memory_fts%'")}
        if not hub.MEMORY_FTS[0]:
            return self.assertEqual(shadow, set())
        self.assertTrue({"memory_fts", "memory_fts_data", "memory_fts_config"} <= shadow)
        self.assertTrue(hub.q("SELECT 1 FROM memory_fts_config LIMIT 1"))
        self.assertIn("BLOB", [r["type"] for r in hub.q("PRAGMA table_info(memory_fts_data)")])

    def test_building_it_twice_refuses_nothing(self):
        self.build(self.FIRST_PUSH)
        self.assertEqual(hub.build_schema(), [])
        self.assertEqual(hub.build_schema(), [])


class StartText(Base):
    """Slot 4 of the per-task block (AUTONOMY.md 6.4): every lesson that matches the work, by tag and by words, inside
    one bound of characters, with no row cap."""

    def test_a_session_with_no_memories_is_told_that_what_it_learns_dies_with_it(self):
        said = hub.start_text("vps", self.task)
        self.assertIn("You have written no memories yet.", said)
        self.assertIn("remember keeps one lesson", said)

    def test_every_lesson_that_matches_and_no_fixed_cap(self):
        mine = self.lessons(9)                                      # nine about acme/web, which the task names
        self.remember(about="stripe", text="A refund over 50 EUR answers 402 with the test key.",
                      prevents="A wrong reading.")
        said = self.block()
        self.assertIn("Your own memory: 10 lessons. These 9 match this task, the ones whose tag it names first:",
                      said)
        self.assertEqual(len(self.shown(said)), 9)
        self.assertNotIn("M-10", said)                              # stripe: nothing in this task names it
        self.assertTrue(all("[acme/web] Lesson" in x for x in self.shown(said)))
        self.assertTrue(all(mine))
        # whole, not shortened
        self.assertIn("- M-1 [acme/web] Lesson 0 on the deploy step: number 0. (in T-1)", said)
        self.assertIn("not rules", said)
        self.assertIn("check one before a step depends on it", said)          # memory phase 2: test before relying
        # and it stands beside the profile, which is the other thing a session needs in front of it
        full = hub.start_text("vps", self.task)
        self.assertIn(said.strip(), full)
        self.assertIn(f"Read {', '.join(hub.rules_files(hub.rules_parts('vps')))} and profiles/vps.md", full)

    def test_a_lesson_matches_by_its_words_too(self):
        self.remember(about="postgres", text="The smoke of the deploy needs the postgres pool at 20.",
                      prevents="A red smoke that is the pool.")
        self.remember(about="stripe", text="A refund over 50 EUR answers 402 with the test key.",
                      prevents="A wrong reading.")
        said = self.block()
        self.assertIn("This one matches this task, by its words:", said)
        self.assertIn("- M-1 [postgres] The smoke of the deploy needs", said)
        self.assertNotIn("M-2", said)
        with patch.object(hub, "MEMORY_FTS", [False]):              # a machine without FTS5 matches the words too
            self.assertIn("- M-1 [postgres]", self.block())

    def test_the_ones_whose_tag_the_task_names_come_first(self):
        self.remember(about="postgres", text="The smoke of the deploy needs the postgres pool at 20.",
                      prevents="A red smoke that is the pool.")
        self.remember(about="acme/web", text="The customer of acme/web is told before a deploy.",
                      prevents="A surprised customer.")
        lines = self.shown(self.block())
        self.assertTrue(lines[0].startswith("- M-2 [acme/web]"), lines)
        self.assertTrue(lines[1].startswith("- M-1 [postgres]"), lines)
        # a tag is a word of the task's own, not part of one: "web" is not in "website"
        self.remember(about="web", text="Unrelated words entirely.", prevents="Nothing.")
        site = self.new_task(title="Move the website", details="the website moves")
        self.assertNotIn("[web]", self.block(site))

    def test_a_task_that_matches_nothing_gets_the_tags_instead(self):
        self.remember(about="stripe", text="A refund over 50 EUR answers 402 with the test key.",
                      prevents="A wrong reading.")
        said = self.block(self.new_task(title="Write the October report", details="numbers for the owner"))
        self.assertIn('Your own memory: 1 lesson, and none matches this task\'s words. Your tags: "stripe" (1).', said)
        self.assertEqual(self.shown(said), [])

    def whole_part(self, said):
        """The part of a start block that shows lessons whole: everything before the line of what did not fit."""
        return said.split(" did not fit whole")[0]

    def test_one_bound_of_characters_for_whole_lessons_and_one_line_for_each_further_match(self):
        """A row is not a cost: the bound is in characters and holds every match that fits whole (3,000 since memory
        phase 3, decision 44); every further match gets one line of its own, twenty at most, which no reading counts
        as shown."""
        for n in range(40):
            self.remember(about="acme/web", text=f"Lesson {n} on the deploy: " + f"word{n} " * 140,
                          prevents=f"Mistake {n}.", new=True)
        said = self.block()
        self.assertEqual(hub.MEMORY_START_CHARS, 3000)
        self.assertLessEqual(len(self.whole_part(said)), hub.MEMORY_START_CHARS)
        shown = self.shown(said)
        self.assertGreaterEqual(len(shown), 2)
        self.assertTrue(all("…" not in x for x in shown))           # each one whole
        more = next(x for x in said.split("\n") if "more match" in x)
        self.assertIn(f"{40 - len(shown)} more match this task and did not fit whole: recall memory=\"M-<id>\" "
                      f"gives one whole.", more)
        index = [x for x in said.split("\n") if x.startswith("  M-")]
        self.assertEqual(len(index), hub.MEMORY_INDEX_LINES)
        self.assertTrue(all(x.endswith("…") and "[acme/web] Lesson" in x and len(x) < 110 for x in index), index)
        self.assertIn(f"  and {40 - len(shown) - hub.MEMORY_INDEX_LINES} more.", said)
        # a line is no showing: only the lessons shown whole are recorded as shown
        fit = hub.memory_start_fit("vps", self.task)
        self.assertEqual([hub.mref(m) for m in fit[3]], [x.split(" ")[1] for x in shown])
        hub.TEAM["settings"] = {"memory.start_chars": 2000}         # the owner's setting is the bound
        small = self.block()
        self.assertLessEqual(len(self.whole_part(small)), 2000)
        self.assertLess(len(self.shown(small)), len(shown))

    def test_a_task_of_a_duty_starts_with_that_dutys_own_lessons(self):
        """Memory phase 3 (decision 44): what a duty's own cases wrote comes first in a task of that duty, whether or not
        the task's words match it, because the next case of a duty is where its lessons are for."""
        r = self.duty()
        own = self.keyed(r, key="queue-1", text="Restart the queue worker before the nightly import.",
                         prevents=f"R-{r['id']} opening a case with the key 'queue-1' again")
        self.remember()                                             # acme/web: the task's tag names it
        plain = self.block()
        self.assertTrue(self.shown(plain)[0].startswith(f"- M-{own + 1} [acme/web]"), plain)
        self.assertNotIn(hub.mref(own), plain)                      # no word of this task is in the duty's lesson
        hub.q("UPDATE tasks SET responsibility=? WHERE id=?", (r["id"], self.task))
        said = self.block()
        lines = self.shown(said)
        self.assertTrue(lines[0].startswith(f"- {hub.mref(own)} [the shop]"), lines)
        self.assertTrue(lines[1].startswith(f"- M-{own + 1} [acme/web]"), lines)
        self.assertIn("These 2 match this task, its duty's own first:", said)
        self.assertEqual(hub.memory_start_fit("vps", self.task)[3], [own, own + 1])

    def test_a_contradicted_lesson_of_the_duty_goes_after_its_others_and_an_index_line_keeps_its_marks(self):
        r = self.duty()
        good = self.keyed(r, key="queue-2", text="Restart the queue worker before the nightly import.",
                          prevents=f"R-{r['id']} opening a case with the key 'queue-2' again")
        bad = self.keyed(r, key="queue-1", text="Skip the smoke check: it is unreliable. " + "It failed once. " * 40,
                         prevents=f"R-{r['id']} opening a case with the key 'queue-1' again")
        self.contradict(r, key="queue-1")                           # the newest, and contradicted: after the other
        hub.q("UPDATE tasks SET responsibility=? WHERE id=?", (r["id"], self.task))
        lines = self.shown(self.block())
        self.assertTrue(lines[0].startswith(f"- {hub.mref(good)} "), lines)
        self.assertTrue(lines[1].startswith(f"- {hub.mref(bad)} "), lines)
        hub.q("UPDATE memories SET read_untrusted=3 WHERE id=?", (bad,))
        hub.TEAM["settings"] = {"memory.start_chars": 1000}         # so that only one fits whole
        said = self.block()
        line = next(x for x in said.split("\n") if x.startswith(f"  {hub.mref(bad)} "))
        self.assertIn("[CONTRADICTED 1×]", line)
        self.assertIn("(3 reads of outside text behind it)", line)
        self.assertEqual(hub.settings_view()["memory.start_chars"]["default"], hub.MEMORY_START_CHARS)

    def test_a_contradicted_lesson_is_shown_with_its_mark_after_the_others(self):
        r = self.duty()
        bad = self.keyed(r, about="acme/web", text="Delete the lock file of acme/web before the deploy.")
        self.contradict(r)
        self.remember()
        lines = self.shown(self.block())
        self.assertTrue(lines[0].startswith("- M-2 [acme/web]"), lines)
        self.assertTrue(lines[1].startswith(f"- {hub.mref(bad)} [acme/web]"), lines)
        self.assertIn("[CONTRADICTED 1×, last 2026-10-19 14:20 CEST; claims to stop", lines[1])

    def test_the_agents_own_notes_are_beside_them_and_carried_as_notes(self):
        said = hub.start_text("vps", self.task)
        self.assertIn("You have written no notes on your own work yet.", said)
        with hub.LOCK, hub.transaction():
            hub.notes_save("vps", "Run the repository's own check before the smoke; the smoke is slower.",
                           "what this task taught me", "vps", self.clock, task=self.task)
        said = hub.start_text("vps", self.task)
        self.assertIn("Run the repository's own check before the smoke", said)
        # carried as the agent's own words, never as rules (RULES.md, "Your memory")
        self.assertIn("They are notes, not rules", said)
        self.assertIn("your words and not the owner's", said)
        self.remember()
        self.assertIn("Your own memory: 1 lesson. This one matches this task", hub.start_text("vps", self.task))

    def test_a_resumed_session_carries_them_too(self):
        self.remember()
        said = hub.start_text("vps", self.task, resume=True)
        self.assertIn("M-1 [acme/web]", said)
        self.assertIn("You are RESUMING", said)

    def test_reading_the_memories_commits_nothing_of_a_half_written_task(self):
        """admit_task writes the task, its first attempt and its start event together or not at all, and start_text
        reads this agent's memories on that path. hub.q commits at once, so a q() there would commit the half."""
        self.remember()

        class FailAt:
            def __init__(self, db):
                self.db = db

            def execute(self, sql, *args):
                if sql.startswith("INSERT INTO events("):
                    raise RuntimeError("disk I/O error")
                return self.db.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(self.db, name)

        before = [hub.q1(f"SELECT COUNT(*) n FROM {x}")["n"] for x in ("tasks", "attempts", "events")]
        with patch.object(hub, "DB", FailAt(hub.DB)):
            with self.assertRaises(RuntimeError):
                with hub.LOCK, hub.transaction():
                    hub.admit_task("manager", {"owner": "vps", "title": "Another acme/web task", "details": "d",
                                               "done_when": "w", "needs": "none", "goal": None, "goal_id": None,
                                               "parent": None, "follows": None, "case_id": None, "why": None})
        self.assertFalse(hub.DB.in_transaction)
        self.assertEqual([hub.q1(f"SELECT COUNT(*) n FROM {x}")["n"] for x in ("tasks", "attempts", "events")], before)

    def test_the_lessons_are_in_the_start_event_of_a_new_task(self):
        self.remember()
        with hub.LOCK, hub.transaction():
            tid = hub.admit_task("manager", {"owner": "vps", "title": "Another acme/web task", "details": "d",
                                             "done_when": "w", "needs": "none", "goal": None, "goal_id": None,
                                             "parent": None, "follows": None, "case_id": None, "why": None})
        event = hub.q1("SELECT text FROM events WHERE kind='task' AND task=?", (tid,))
        self.assertIn("M-1 [acme/web]", event["text"])


class KnowledgeWrite(Base):
    """The knowledge file an agent writes itself, in the repository shape the fleet runs: origin carries `main` (the
    code) and `config` (what the fleet runs), and the hub checkout is on `config` (test_config_ref.py)."""

    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-memory-knowledge-"))
        seed = self.root / "seed"
        (seed / "profiles").mkdir(parents=True)
        (seed / "knowledge/owner").mkdir(parents=True)
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        (seed / "profiles/vps.md").write_text(PROFILE)
        (seed / "knowledge/services.md").write_text("# Services\n\nStripe: through the dashboard.\n")
        (seed / "knowledge/suppliers.md").write_text("# Suppliers\n\nStripe: through the dashboard.\n")
        (seed / "knowledge/owner/brand.md").write_text("# Brand\n\nBlue.\n")
        (seed / "hub.py").write_text("# the hub\nVERSION = 1\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("branch", hub.CONFIG_BRANCH, cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", "-b", hub.CONFIG_BRANCH, str(self.root / "origin.git"), str(self.root / "kit"))
        self.kit = self.root / "kit"
        hub.CFG["team_path"] = str(self.kit / "team.json")
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        hub.KNOWLEDGE_CACHE = (None, [])
        self.seeded = git("rev-parse", "HEAD", cwd=self.kit)
        self.addCleanup(self.put_back)

    def put_back(self):
        hub.CFG.pop("team_path", None)
        hub._revision_cache.update(at=0.0, value=None)
        hub._code_diffs.clear()
        hub.KNOWLEDGE_CACHE = (None, [])
        shutil.rmtree(str(self.root), ignore_errors=True)

    def write(self, who="vps", path="knowledge/suppliers.md", text="# Suppliers\n\nStripe: call_api with its key.\n",
              why="Stripe goes through call_api now, not the dashboard.", **more):
        return self.tool(who, "write_knowledge", request_id=str(uuid.uuid4()), path=path, text=text, why=why, **more)

    def file(self, path="knowledge/suppliers.md"):
        return (self.kit / path).read_text()

    def head(self):
        return git("rev-parse", hub.CONFIG_BRANCH, cwd=self.root / "origin.git")

    def begin(self, task=None):
        """The task's attempt and the revision it starts from, as admit_task records them (seen_start_row)."""
        task = task or self.task
        hub.ins("INSERT INTO attempts(task,attempt,created,reason) VALUES(?,1,?,'created')", (task, self.clock))
        hub._revision_cache.update(at=0.0, value=None)
        with hub.LOCK, hub.transaction():
            hub.seen_start_row(task)
        return task

    def test_a_file_that_changed_after_this_session_started_is_not_written_over(self):
        """The article's shared table: of 57 facts that parallel writers put in one page, 41 survived."""
        hub.CFG["artifact_repo"] = str(self.kit)                  # read_knowledge reads the hub checkout
        self.addCleanup(hub.CFG.pop, "artifact_repo", None)
        hub.KNOWLEDGE_CACHE = (None, [])
        self.begin()
        theirs = self.begin(self.new_task())
        said, error = self.write(task=theirs)       # a file that is there: a whole write needs a read of it
        self.assertTrue(error, said)
        self.assertIn("this session has not read it with read_knowledge", said)
        self.assertEqual(self.head(), self.seeded)
        self.ok("vps", "read_knowledge", path="knowledge/suppliers.md")              # this session reads it ...
        hub.KNOWLEDGE_CACHE = (None, [])
        self.ok("vps", "read_knowledge", task=theirs, path="knowledge/suppliers.md")  # ... and so does the other
        said, error = self.write(text="# Suppliers\n\nStripe: through the dashboard.\nAcme: by phone.\n",
                                 why="Acme takes orders by phone.", task=theirs)
        self.assertFalse(error, said)
        after = self.head()
        said, error = self.write()                  # what this session read is the seed
        self.assertTrue(error, said)
        self.assertIn("knowledge/suppliers.md changed after this session read it", said)
        self.assertIn("Read it again with read_knowledge", said)
        self.assertEqual(self.head(), after)
        self.assertIn("Acme: by phone.", self.file())
        hub.KNOWLEDGE_CACHE = (None, [])
        self.ok("vps", "read_knowledge", path="knowledge/suppliers.md")
        said, error = self.write(text="# Suppliers\n\nStripe: call_api with its key.\nAcme: by phone.\n")
        self.assertFalse(error, said)
        self.assertEqual(self.file(), "# Suppliers\n\nStripe: call_api with its key.\nAcme: by phone.\n")
        # its own write is one it has read; the other session has not read it, and is refused in turn
        self.assertFalse(self.write(text="# Suppliers\n\nStripe: call_api.\nAcme: by phone.\n")[1])
        self.assertTrue(self.write(text="# Suppliers\n\nAcme: by phone.\n", task=theirs)[1])

    def test_a_write_the_hub_cannot_place_in_a_session_writes_as_before(self):
        said, error = self.write()                  # a task with no attempt row: no session to hold it to
        self.assertFalse(error, said)

    def test_a_new_attempt_reads_again_and_a_removed_file_is_written_anew(self):
        hub.CFG["artifact_repo"] = str(self.kit)
        self.addCleanup(hub.CFG.pop, "artifact_repo", None)
        hub.KNOWLEDGE_CACHE = (None, [])
        self.begin()
        self.ok("vps", "read_knowledge", path="knowledge/suppliers.md")
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (self.task,))
        with hub.LOCK, hub.transaction():
            hub.attempt_rows(t, "restart", ("vps", "task", self.task, "a start", {}), self.clock)
        said, error = hub.call_tool("vps", "write_knowledge", {
            "request_id": str(uuid.uuid4()), "path": "knowledge/suppliers.md", "text": "# Suppliers\n\nOne.\n",
            "why": "One.", "task_id": hub.tref(self.task)}, ("test-generation", hub.tref(self.task), 2))
        self.assertIn("this session has not read it with read_knowledge", said)     # the read was attempt 1's
        hub.KNOWLEDGE_CACHE = (None, [])
        hub.call_tool("vps", "read_knowledge", {"path": "knowledge/suppliers.md", "task_id": hub.tref(self.task)},
                      ("test-generation", hub.tref(self.task), 2))
        hub.commit_kit_file("knowledge/suppliers.md", None, "The owner removed it")   # the owner removes it
        removed = {"request_id": str(uuid.uuid4()), "path": "knowledge/suppliers.md", "text": "# Suppliers\n\nTwo.\n",
                   "why": "Two.", "task_id": hub.tref(self.task)}
        said, error = hub.call_tool("vps", "write_knowledge", removed, ("test-generation", hub.tref(self.task), 2))
        self.assertTrue(error, said)
        self.assertIn("was removed after this session read it", said)
        gone = self.head()
        self.assertEqual(hub.call_tool("vps", "write_knowledge", removed, ("test-generation", hub.tref(self.task), 2)),
                         (said, error))                     # the repeat of a lost answer writes nothing
        self.assertEqual(self.head(), gone)
        said, error = hub.call_tool("vps", "write_knowledge", dict(removed, request_id=str(uuid.uuid4())),
                                    ("test-generation", hub.tref(self.task), 2))
        self.assertFalse(error, said)
        self.assertEqual(self.file(), "# Suppliers\n\nTwo.\n")

    def test_a_key_shape_is_never_written_to_a_knowledge_file(self):
        key = ("-----BEGIN OPENSSH PRIVATE KEY-----\n" + "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n" * 3
               + "-----END OPENSSH PRIVATE KEY-----\n")
        said, error = self.write(text="# Suppliers\n\nThe deploy key:\n" + key)
        self.assertTrue(error, said)
        self.assertIn("Blocked", said)
        self.assertEqual(self.head(), self.seeded)

    def test_the_commit_says_where_it_was_written_and_what_its_session_had_read(self):
        hub.ins("INSERT INTO calls(ts,agent,task,attempt,name,args,ok,detail) VALUES(?,?,?,1,'call_api','{}',1,'')",
                (self.clock, "vps", self.task))
        self.assertFalse(self.write()[1])
        message = git("log", "-1", "--format=%B", cwd=self.kit)
        self.assertIn(f"Fleet-Task: {hub.tref(self.task)}", message)
        self.assertIn("Fleet-Outside-Reads: 1", message)
        self.assertIn("1 read of outside text", message)

    def test_an_agent_writes_the_knowledge_file_its_own_profile_lists(self):
        said, error = self.write()
        self.assertFalse(error, said)
        self.assertIn("knowledge/suppliers.md is written as", said)
        self.assertEqual(self.file(), "# Suppliers\n\nStripe: call_api with its key.\n")
        # one commit of the configuration ref, which the hub checkout took in
        self.assertEqual(self.head(), git("rev-parse", "HEAD", cwd=self.kit))
        self.assertNotEqual(self.head(), self.seeded)

    def test_the_commit_says_who_wrote_it_why_and_why_without_asking(self):
        self.assertFalse(self.write()[1])
        message = git("log", "-1", "--format=%an <%ae>%n%B", cwd=self.kit)
        self.assertIn("Fleet agent vps <vps@fleet.invalid>", message)
        self.assertIn("vps changed knowledge/suppliers.md: Stripe goes through call_api now", message)
        self.assertIn("directly and without asking", message)            # why directly, and not as a proposal
        self.assertIn("reverts it in one step", message)                 # and what the owner's control is

    def test_a_shared_file_its_profile_does_not_list_is_written_too(self):
        """Plan C17 (the owner, 26 October 2026: no unnecessary gates): every agent writes the fleet's shared knowledge
        files, and the profile's list only says which ones it reads at its start."""
        said, error = self.write(path="knowledge/customers.md")
        self.assertFalse(error, said)
        self.assertIn("knowledge/customers.md is written as", said)
        self.assertNotEqual(self.head(), self.seeded)

    def test_the_owners_own_knowledge_stays_his(self):
        hub.CFG["team_path"] = str(self.kit / "team.json")
        with patch.object(hub, "profile_knowledge_files", lambda agent, rev: ["knowledge/owner/brand.md"]):
            said, error = self.write(path="knowledge/owner/brand.md", text="# Brand\n\nRed.\n", why="Red now.")
        self.assertTrue(error, said)
        self.assertIn("the owner's own knowledge", said)
        self.assertEqual(self.file("knowledge/owner/brand.md"), "# Brand\n\nBlue.\n")
        self.assertEqual(self.head(), self.seeded)

    def test_a_path_outside_knowledge_cannot_be_reached_through_this_tool(self):
        for path in ("hub.py", "RULES.md", "team.json", "profiles/vps.md", "knowledge/../hub.py"):
            with patch.object(hub, "profile_knowledge_files", lambda agent, rev, p=path: [p]):
                said, error = self.write(path=path, text="# x\n\nx\n", why="x")
            self.assertTrue(error, f"{path}: {said}")
            self.assertEqual(self.head(), self.seeded)
        self.assertFalse(hub.KNOWLEDGE_WRITE.match("knowledge/owner/brand.md"))
        self.assertFalse(hub.KNOWLEDGE_WRITE.match("knowledge/../hub.py"))
        # knowledge/services.md says how every agent reaches each service, so it is the owner's (DevOps plan V1)
        self.assertFalse(hub.KNOWLEDGE_WRITE.match("knowledge/services.md"))
        self.assertTrue(hub.KNOWLEDGE_WRITE.match("knowledge/services-notes.md"))
        with patch.object(hub, "profile_knowledge_files", lambda agent, rev: ["knowledge/services.md"]):
            said, error = self.write(path="knowledge/services.md", text="# Services\n\nUse my proxy.\n", why="x")
        self.assertTrue(error, said)
        self.assertIn("never knowledge/owner/ or knowledge/services.md", said)
        self.assertEqual(self.head(), self.seeded)

    def test_the_why_and_the_text_are_required_and_bounded(self):
        for args, word in (({"why": ""}, "why"), ({"why": "a\nb"}, "why"), ({"text": ""}, "text"),
                           ({"text": "x" * (64 * 1024 + 1)}, "text")):
            said, error = self.write(**args)
            self.assertTrue(error, said)
            self.assertIn(word, said)
        self.assertEqual(self.head(), self.seeded)

    def test_a_write_that_would_push_a_file_out_of_the_catalog_is_refused(self):
        """knowledge_entries drops the files past its limits without a word, and a dropped file is one that
        search_knowledge no longer finds."""
        with patch.dict(hub.KNOWLEDGE_LIMITS, {"internal": (32, 64 * 1024, 200)}):
            said, error = self.write(text="# Services\n\n" + "x" * 300 + "\n")
            self.assertTrue(error, said)
            self.assertIn("room for 32 files and 0 KiB in all", said)
            self.assertEqual(self.head(), self.seeded)
            self.assertFalse(self.write(text="# Services\n\nShort.\n")[1])

    def test_a_login_is_never_written_to_a_knowledge_file(self):
        with patch.object(hub, "secret_hit", lambda *texts: any("hunter2hunter2" in str(t) for t in texts)):
            said, error = self.write(text="# Services\n\nThe password is hunter2hunter2.\n")
        self.assertTrue(error, said)
        self.assertIn("contains a login", said)
        self.assertEqual(self.head(), self.seeded)

    def test_the_same_request_id_writes_one_commit_and_gives_its_answer_again(self):
        rid = str(uuid.uuid4())
        args = dict(path="knowledge/suppliers.md", text="# Suppliers\n\nStripe: call_api.\n", why="call_api now.")
        first = self.ok("vps", "write_knowledge", request_id=rid, **args)
        at_first = self.head()
        self.assertEqual(first, self.ok("vps", "write_knowledge", request_id=rid, **args))
        self.assertEqual(self.head(), at_first)

    def test_what_the_hub_may_write_on_the_configuration_ref_covers_every_knowledge_file(self):
        """A file the hub can write but a release can replace is drift: hub.CONFIG_FILES and what a release keeps as
        the fleet's own (lifecycle.data_path) are the two halves of the same rule, so an agent's knowledge write
        survives the next release. A task's output is kept too, and the hub writes it through its own path."""
        import lifecycle
        for path in ("team.json", "profiles/vps.md", "knowledge/services.md", "knowledge/owner/brand.md"):
            self.assertTrue(hub.CONFIG_FILES.match(path), path)
            self.assertTrue(lifecycle.data_path(path), path)
        for path in ("hub.py", "RULES.md", "CLAUDE.md", "release.json"):
            self.assertFalse(hub.CONFIG_FILES.match(path), path)
            self.assertFalse(lifecycle.data_path(path), path)
        self.assertFalse(hub.CONFIG_FILES.match("outputs/T-1/result.md"))
        self.assertTrue(lifecycle.data_path("outputs/T-1/result.md"))
        # CONFIG_FILES is the half that meets a path from outside; a release reads real tree paths only.
        for path in ("knowledge/owner/../../hub.py", "profiles/../hub.py", "knowledge/../hub.py"):
            self.assertFalse(hub.CONFIG_FILES.match(path), path)

    def test_the_backup_takes_every_knowledge_file_and_not_only_the_owners(self):
        files = hub.owner_files()
        self.assertEqual(sorted(files), ["knowledge/owner/brand.md", "knowledge/services.md", "knowledge/suppliers.md",
                                         "profiles/vps.md", "team.json"])


class Shown(Base):
    """What a start showed (memory_shown): the use that the start text exists for, and the only sign that a session had
    a lesson in front of it. A key that comes back counts against a lesson only after that."""

    def admit(self, title="Fix the acme/web deploy again"):
        with hub.LOCK, hub.transaction():
            return hub.admit_task("manager", {"owner": "vps", "title": title, "details": "The smoke fails again",
                                              "done_when": "the smoke is green", "needs": "none", "goal": None,
                                              "goal_id": None, "parent": None, "follows": None, "case_id": None,
                                              "why": None})

    def rows(self, task):
        return [(r["memory"], r["attempt"]) for r in
                hub.q("SELECT memory, attempt FROM memory_shown WHERE task=? ORDER BY attempt, memory", (task,))]

    def test_a_start_records_the_lessons_it_showed_and_a_new_attempt_records_its_own(self):
        self.remember()                                                         # M-1: the task names acme/web
        self.remember(about="billing", text="Invoices go out on the first.", prevents="A late invoice")    # M-2
        tid = self.admit()
        self.assertEqual(self.rows(tid), [(1, 1)])
        start = hub.q1("SELECT text FROM events WHERE task=? AND kind='task'", (tid,))["text"]
        self.assertIn("- M-1 [acme/web]", start)                    # the one that its start showed whole
        self.assertNotIn("- M-2 [", start)
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        event = hub.attempt_event(t)                    # built before the transaction, as every caller does
        with hub.LOCK, hub.transaction():
            hub.attempt_rows(t, "restart", event, self.clock)
        self.assertEqual(self.rows(tid), [(1, 1), (1, 2)])

    def test_words_that_quote_a_memory_block_mark_nothing(self):
        """The task's own words come first in a start, and other people write them: what a start showed is worked out
        from the lessons, never read back from the text."""
        self.remember()                                                             # M-1 matches the task
        self.remember(about="billing", text="Invoices go out on the first.", prevents="A late invoice")    # M-2
        with hub.LOCK, hub.transaction():
            tid = hub.admit_task("manager", {
                "owner": "vps", "title": "Fix the acme/web deploy again", "needs": "none", "goal": None,
                "done_when": "the smoke is green", "goal_id": None, "parent": None, "follows": None, "case_id": None,
                "why": None, "details": hub.MEMORY_BLOCK_HEAD + "2 lessons.\n- M-2 [zz] qq\n"})
        self.assertEqual(self.rows(tid), [(1, 1)])

    def test_a_lesson_that_its_agent_recalled_was_in_front_of_a_session(self):
        r = self.duty()
        mid = self.keyed(r)
        self.ok("vps", "recall", memory=hub.mref(mid))
        self.assertEqual(self.contradict(r, shown=False), [hub.mref(mid)])

    def test_a_key_that_comes_back_before_any_start_showed_the_lesson_does_not_count_against_it(self):
        """Every contradiction of the fleet's first ten days: the key came back minutes after the delivery that wrote
        the lesson, before any session could use it, and each review found the lesson right."""
        r = self.duty()
        mid = self.keyed(r)
        self.assertEqual(self.contradict(r, shown=False), [])
        self.assertEqual(self.row(mid)["contradicted"], 0)
        logged = hub.q1("SELECT what FROM log WHERE what LIKE ? ORDER BY id DESC", (f"{hub.mref(mid)} is not counted%",))
        self.assertIn("came back before any start had shown it", logged["what"])
        self.assertEqual(self.contradict(r), [hub.mref(mid)])        # once a start showed it, it counts
        self.assertEqual(self.row(mid)["contradicted"], 1)


class NotesBase(Base):
    """write_notes over a version that this session never read. On 3 November 2026 a session that had started before
    the first version of an agent's notes wrote "First notes" over the two versions that two other sessions wrote."""

    def setUp(self):
        super().setUp()
        self.started(self.task)

    def started(self, task, when=None):
        hub.ins("INSERT INTO attempts(task,attempt,created,reason) VALUES(?,1,?,'created')",
                (task, self.clock if when is None else when))
        return task

    def notes(self, text, task=None):
        return self.tool("vps", "write_notes", task=task, request_id=str(uuid.uuid4()), text=text,
                         why="What the work taught me.")

    def test_notes_that_another_session_wrote_after_this_one_started_are_shown_and_not_written_over(self):
        other = self.started(self.new_task())
        self.clock += 60
        said, error = self.notes("Look for my other sessions first.", task=other)
        self.assertFalse(error, said)
        self.clock += 60
        said, error = self.notes("First notes: the check timeout cap is 60 s.")
        self.assertTrue(error, said)
        self.assertIn("Your notes changed after this session read them: revision 1", said)
        self.assertIn("Look for my other sessions first.", said)            # as they stand, to merge into
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM agent_notes")["n"], 1)
        said, error = self.notes("Look for my other sessions first. The check timeout cap is 60 s.")
        self.assertFalse(error, said)                                       # the refusal showed them: read
        self.assertIn("revision 2", said)

    def test_a_refused_write_is_refused_again_for_the_same_request_id(self):
        """mcp.py gives up on an answer after 20 seconds while the hub is busy, and RULES.md asks for the same
        request_id again: that repeat found the notes read, and wrote the words that the refusal said were not
        written."""
        other = self.started(self.new_task())
        self.clock += 60
        self.assertFalse(self.notes("Theirs.", task=other)[1])
        self.clock += 60
        args = dict(request_id=str(uuid.uuid4()), text="Mine, from before theirs.", why="What the work taught me.")
        first = self.tool("vps", "write_notes", **args)
        self.assertTrue(first[1], first[0])
        self.assertEqual(self.tool("vps", "write_notes", **args), first)
        self.assertEqual(hub.agent_notes_text("vps"), "Theirs.")
        said, error = self.tool("vps", "write_notes", **dict(args, text="Theirs. Mine."))
        self.assertTrue(error, said)
        self.assertIn("already used for another call", said)
        self.assertFalse(self.tool("vps", "write_notes", **dict(args, request_id=str(uuid.uuid4()),
                                                                text="Theirs. Mine."))[1])
        self.assertEqual(hub.agent_notes_text("vps"), "Theirs. Mine.")

    def test_notes_that_stood_at_the_start_and_the_sessions_own_writes_go_through(self):
        other = self.started(self.new_task(), when=self.clock - 120)
        self.clock -= 60
        self.assertFalse(self.notes("One.", task=other)[1])             # written before this session started
        self.clock += 120
        self.assertFalse(self.notes("One. Two.")[1])
        self.assertFalse(self.notes("One. Two. Three.")[1])            # a version it wrote itself is one it read

    def test_see_notes_is_a_read_that_a_write_builds_on(self):
        other = self.started(self.new_task())
        self.clock += 60
        self.assertFalse(self.notes("Theirs.", task=other)[1])
        self.ok("vps", "see_notes")
        self.assertFalse(self.notes("Theirs. Mine.")[1])

    def test_a_new_attempt_starts_from_the_notes_as_they_stand_then(self):
        other = self.started(self.new_task())
        self.ok("vps", "see_notes")                                     # attempt 1 has read what there is
        self.clock += 60
        self.assertFalse(self.notes("Theirs.", task=other)[1])
        self.clock += 60
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (self.task,))
        event = hub.attempt_event(t)                    # built before the transaction, as every caller does
        with hub.LOCK, hub.transaction():
            hub.attempt_rows(t, "restart", event, self.clock)
        said, error = hub.call_tool("vps", "write_notes", {"request_id": str(uuid.uuid4()), "text": "Theirs. Mine.",
                                                           "why": "What the work taught me.",
                                                           "task_id": hub.tref(self.task)},
                                    ("test-generation", hub.tref(self.task), 2))      # the new session's own
        self.assertFalse(error, said)


class NotesAtStart(Base):
    """The notes version that a start showed is the base of its session's write_notes: read from the start text,
    because a restart builds its text before its transaction and a parallel write can land in between."""

    def admit(self):
        with hub.LOCK, hub.transaction():
            return hub.admit_task("manager", {"owner": "vps", "title": "Tidy the deploy notes", "details": "d",
                                              "done_when": "w", "needs": "none", "goal": None, "goal_id": None,
                                              "parent": None, "follows": None, "case_id": None, "why": None})

    def write(self, task, text, attempt=1):
        return hub.call_tool("vps", "write_notes", {"request_id": str(uuid.uuid4()), "text": text,
                                                    "why": "What the work taught me.", "task_id": hub.tref(task)},
                             ("test-generation", hub.tref(task), attempt))

    def test_a_task_started_with_the_notes_of_its_start_and_another_write_is_not_lost(self):
        other = self.admit()
        self.assertFalse(self.write(other, "One.")[1])                  # revision 1
        mine = self.admit()                                             # its start shows revision 1
        self.assertEqual(hub.kv_get(f"{hub.SEEN_KEY}{mine}:notes"), "1")
        self.assertFalse(self.write(other, "One. Two.")[1])             # revision 2, at the same clock
        said, error = self.write(mine, "One. Mine.")
        self.assertTrue(error, said)
        self.assertIn("revision 2", said)

    def test_a_restart_holds_the_notes_its_text_was_built_with(self):
        mine, other = self.admit(), self.admit()
        self.assertFalse(self.write(other, "One.")[1])
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (mine,))
        event = hub.attempt_event(t)                                    # built before its transaction ...
        self.assertFalse(self.write(other, "One. Two.")[1])             # ... and a write lands in between
        with hub.LOCK, hub.transaction():
            hub.attempt_rows(t, "restart", event, self.clock)
        self.assertEqual(hub.kv_get(f"{hub.SEEN_KEY}{mine}:notes"), "1")
        said, error = self.write(mine, "One. Mine.", attempt=2)
        self.assertTrue(error, said)
        self.assertIn("One. Two.", said)

    def test_the_managers_standing_session_is_held_to_its_start_as_well(self):
        hub.ins("INSERT INTO session_credentials(sha256,agent,kind,generation,created) VALUES('s','manager',"
                "'standing','test-generation',?)", (self.clock,))
        with hub.LOCK, hub.transaction():
            hub.notes_save("manager", "One.", "first", "manager", self.clock + 60)      # a task of the manager's
        said, error = hub.call_tool("manager", "write_notes", {"request_id": str(uuid.uuid4()), "text": "Mine.",
                                                               "why": "What the work taught me."})
        self.assertTrue(error, said)
        self.assertIn("Your notes changed after this session read them", said)
        said, error = hub.call_tool("manager", "write_notes", {"request_id": str(uuid.uuid4()), "text": "One. Mine.",
                                                               "why": "What the work taught me."})
        self.assertFalse(error, said)
        said, error = hub.call_tool("manager", "write_notes", {"request_id": str(uuid.uuid4()),
                                                               "text": "One. Mine. More.",
                                                               "why": "What the work taught me."})
        self.assertFalse(error, said)                                    # its own write is one it has read


class Outside(Base):
    """The one count on a lesson that the agent did not choose (untrusted_reads): it covers the reads of its own history
    that gave other people's words back, and a lesson written again keeps the larger count."""

    def test_a_read_of_history_that_gives_other_peoples_words_back_counts_as_outside_text(self):
        hub.history_outside_read({"task_id": hub.tref(self.task)}, ["result", "note", "owner_chat"])
        self.assertEqual(hub.untrusted_reads(self.task), 0)            # its own words, and the owner's
        hub.history_outside_read({"task_id": hub.tref(self.task)}, ["result", "message"])
        hub.history_outside_read({"task_id": hub.tref(self.task)}, ["tool"])
        hub.history_outside_read({"task_id": hub.tref(self.task)}, ["conversation"])
        self.assertEqual(hub.untrusted_reads(self.task), 3)
        self.remember()
        self.assertEqual(self.row()["read_untrusted"], 3)

    def test_search_history_counts_a_message_of_another_agent_that_it_gave_back(self):
        with hub.LOCK, hub.transaction():
            hub.history_note("vps", "message", "AM-7", "studio says the supplier invoices arrive late every month",
                             task=self.task, person="studio")
        said = self.ok("vps", "search_history", query="supplier invoices")
        self.assertIn("AM-7", said)
        self.assertEqual(hub.untrusted_reads(self.task), 1)

    def test_read_history_counts_a_message_of_another_agent_that_it_gave_back(self):
        with hub.LOCK, hub.transaction():
            hub.history_note("vps", "message", "AM-8", "studio says the supplier wants a call first",
                             task=self.task, person="studio")
        self.assertIn("the supplier wants a call first", self.ok("vps", "read_history", ref="AM-8"))
        self.assertEqual(hub.untrusted_reads(self.task), 1)

    def test_the_wake_texts_and_a_contacts_messages_of_the_task_count_too(self):
        hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,state,task,created) VALUES(1,1,?, 'started',?,?)",
                (self.clock, self.task, self.clock))
        hub.ins("INSERT INTO conversation_messages(conversation,who,text,created,task) VALUES(1,'person','hi',?,?)",
                (self.clock, self.task))
        self.assertEqual(hub.untrusted_reads(self.task), 2)

    def test_a_lesson_written_again_keeps_the_larger_outside_count(self):
        self.remember()
        hub.q("UPDATE memories SET read_untrusted=3 WHERE id=1")
        other = self.new_task()
        self.ok("vps", "remember", task=other, request_id=str(uuid.uuid4()), about="acme/web",
                text=LESSON + " And lint first.", prevents=PREVENTS, instead_of="M-1")
        self.assertEqual(self.row(2)["read_untrusted"], 3)              # its session read nothing outside


if __name__ == "__main__":
    unittest.main()

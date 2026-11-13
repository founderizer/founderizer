"""Checks that print lines (AUTONOMY.md P4, section 6.5) and lead checks in batches (P9.11): lane L4.

The hub side runs an in-process hub with its HTTP server, a temporary database, a set clock and a stand-in helper
that posts results; the helper side runs the real check runner on stand-in code. No AI."""
import fnmatch
import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import lifecycle
import wakeups as w
from test_release_turns import helper_reports
from test_ui_api import OwnerAPI

CODEX_FULL = "codex --no-daemon --sandbox danger-full-access --ask-for-approval never {prompt}"
CLAUDE_FULL = "claude --permission-mode dontAsk {settings} {prompt}"
EVERY = {"kind": "every", "minutes": 15}
TASK = {"title": "New tickets", "details": "", "done_when": "Each new ticket has a draft.", "needs": "none",
        "goal_id": None}
LINES = {"code": "print('T-81 new ticket')\n"}              # the line form: no condition, no repeat
VALUE = {"code": "import json\nprint(json.dumps({'value': 11}))\n", "condition": {"op": ">", "value": 10}}
FEATURES = ("trigger_check", "trigger_code", "check_lines")
SECRET = "Pr4ct!ce-Login#2026"


def load_tests(loader, _tests, _pattern):
    """Only the cases that each class of this file defines itself: Lines gets its server from OwnerAPI."""
    suite = unittest.TestSuite()
    for cls in (Module, Lines, Runner):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Module(unittest.TestCase):
    """The pure decisions of wakeups.py."""

    def test_only_lines_that_the_last_accepted_run_did_not_print_are_new(self):
        self.assertEqual(w.new_lines(["T-1 a", "T-2 b", "T-1 a"], []), ["T-1 a", "T-2 b"])
        self.assertEqual(w.new_lines(["T-1 a", "T-2 b", "T-3 c"], ["T-1 a", "T-2 b"]), ["T-3 c"])
        self.assertEqual(w.new_lines(["T-1 a"], ["T-1 a", "T-9 gone"]), [])
        self.assertEqual(w.new_lines(["T-1 a, changed"], ["T-1 a"]), ["T-1 a, changed"])    # a changed line is new

    def test_a_first_progress_line_is_never_a_wake_line(self):
        self.assertEqual(w.progress_of(["progress 87", "T-1 late"]), (87.0, ["T-1 late"]))
        self.assertEqual(w.progress_of(["progress -2.5"]), (-2.5, []))
        self.assertEqual(w.progress_of(["T-1 late", "progress 87"]), (None, ["T-1 late", "progress 87"]))
        self.assertEqual(w.progress_of(["progress ok"]), (None, ["progress ok"]))
        self.assertEqual(w.progress_of([]), (None, []))

    def test_one_open_wake_and_no_line_lost(self):
        d = w.lines_decision
        self.assertEqual(d([], False, None, None), ("quiet", None))
        self.assertEqual(d(["T-1"], True, None, None), ("not_started", "Check now never starts a wake-up."))
        self.assertEqual(d(["T-1"], False, {"task": 4}, "limit"), ("joined", None))
        self.assertEqual(d(["T-1"], False, None, "vps is at its usage limit."), ("waiting", "vps is at its usage limit."))
        self.assertEqual(d(["T-1"], False, None, None), ("started", None))

    def test_lines_are_one_json_array_and_a_long_list_is_split_not_dropped(self):
        self.assertEqual(w.lines_text(['T-1 "urgent" ]', "ñ"]), '["T-1 \\"urgent\\" ]", "ñ"]')
        lines = [f"T-{i} " + "x" * 50 for i in range(100)]
        head, rest = w.split_lines(lines, 1000)
        self.assertEqual(head + rest, lines)
        self.assertLessEqual(len(w.lines_text(head)), 1000)
        self.assertEqual(w.split_lines(["y" * 5000], 1000), (["y" * 5000], []))      # one line always goes

    def test_the_line_form_is_known_and_any_other_form_reads_as_quiet(self):
        lines = w.saved_check(LINES, "vps")[0]
        self.assertEqual(lines["form"], "lines")
        self.assertTrue(w.check_known(lines))
        self.assertFalse(w.check_known(dict(lines, form="events")))
        self.assertFalse(w.check_known(dict(lines, code=None)))
        self.assertTrue(w.check_known(w.saved_check(VALUE, "vps")[0]))
        self.assertIn("each line that it prints and its last run did not print wakes vps", w.check_text(lines, "vps"))

    def test_a_check_s_numbers_read_whole(self):
        """With :g a value check's 10485760 read "1.04858e+07" (adversarial review, 28 October 2026)."""
        for number, said in ((10485760, "10485760"), (10485760.0, "10485760"), (1000000.5, "1000000.5"),
                             (0.1 + 0.2, "0.3"), (-3, "-3"), (2.5e-7, "2.5e-07")):
            self.assertEqual(w.number_text(number), said)
            self.assertEqual(hub.item_number(number), said)
        big = w.saved_check(dict(VALUE, condition={"op": ">", "value": 10485760}), "vps")[0]
        self.assertIn("the value is more than 10485760", w.check_text(big, "vps"))
        self.assertIn("value 10485761", w.run_text({"id": 3, "due": 0, "state": "matched", "value": 10485761.0},
                                                   lambda t: "now"))

    def test_the_save_trigger_text_is_short_and_says_the_line_form(self):
        text = dict((n, d) for n, d, _ in w.TOOL_SPECS)["save_trigger"]
        self.assertLess(len(text), 2000)                                  # it was 3,300 characters
        for words in ("one line for each item that needs the agent now", "beginning with the item's own id",
                      "\"progress <number>\"", "the third failed run in a row", "your read keys",
                      "only an agent itself saves the code of its checks"):
            self.assertIn(words, text)
        self.assertNotIn("run_on", text)
        self.assertNotIn("approve", text)


class Lines(OwnerAPI):
    """The hub's delivery of check lines (AUTONOMY.md 6.5), through its own tools, tables and helper routes."""

    def setUp(self):
        super().setUp()
        hub.TEAM = {"addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3", "seo": "127.0.0.4",
                                  "blog": "127.0.0.5", "shop": "127.0.0.6"},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": [],
                                           "start": CLAUDE_FULL, "allow": ["Bash"]},
                               "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"],
                                       "start": CODEX_FULL},
                               "seo": {"role": "worker", "runtime": "claude", "machine": "seo", "can": ["shell"],
                                       "start": CLAUDE_FULL, "allow": ["Bash"], "reports_to": "lead"},
                               "dev": {"role": "worker", "runtime": "codex", "machine": "shop", "can": ["shell"],
                                       "start": CODEX_FULL, "reports_to": "lead"},
                               "lead": {"role": "lead", "runtime": "claude", "machine": "blog", "can": ["shell"],
                                        "start": CLAUDE_FULL, "allow": ["Bash"]}},
                    "goals": {"timezone": "Europe/Madrid"},
                    "settings": {"checks.lines": True}}
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90, tick=5)
        self.clock = 1791700000.0
        clock = patch.object(hub, "now", lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        for name in hub.TEAM["agents"]:
            hub.touch(name)
            helper_reports(name, *FEATURES)
        self.sessions = {name: self.open_session(name) for name in ("vps", "seo", "dev", "lead")}
        self.first_task = hub.q1("SELECT COALESCE(MAX(id), 0) m FROM tasks")["m"]
        self.first_event = hub.q1("SELECT COALESCE(MAX(id), 0) m FROM events")["m"]

    # ---- the stand-in fleet

    def open_session(self, agent):
        """A real task of `agent`, requested by its boss through the hub's own admission, and its fence context."""
        fields = {"owner": agent, "title": f"Fixture session of {agent}", "details": "", "done_when": "The test ends.",
                  "needs": "none", "goal": None, "goal_id": None, "parent": None, "follows": None, "case_id": None,
                  "why": f"{agent} is the one for it."}
        with hub.transaction():
            tid = hub.admit_task(hub.reports_to(agent), fields)
        return (hub.kv_get("db_id"), hub.tref(tid), 1)

    def tool(self, agent, name, args, context=None):
        return hub.call_tool(agent, name, args, context or self.sessions.get(agent))

    def save(self, caller, request_id, check=LINES, **fields):
        text, error = self.tool(caller, "save_trigger", dict({"request_id": request_id, "schedule": EVERY,
                                                              "task": TASK, "check": check}, **fields))
        self.assertFalse(error, text)
        return hub.q1("SELECT * FROM triggers ORDER BY id DESC LIMIT 1")

    def tick(self, when):
        self.clock = when
        for name in hub.TEAM["agents"]:
            hub.touch(name)
        with hub.LOCK:
            hub.trigger_sweep(when)

    def sent(self, trigger_id=None):
        """The newest check event (of this trigger), as the stand-in helper reads it: (runner, extra)."""
        e = hub.q1("SELECT * FROM events WHERE kind='trigger_check' AND (? IS NULL OR json_extract(extra, "
                   "'$.trigger')=?) ORDER BY id DESC LIMIT 1", (trigger_id, trigger_id))
        return (e["agent"], json.loads(e["extra"])) if e else (None, None)

    def source(self, agent):
        return hub.TEAM["addresses"][hub.TEAM["agents"][agent]["machine"]]

    def post(self, runner, extra, **result):
        return self.request(f"/helper/trigger/{runner}/{extra['run']}", dict({"token": extra["token"], "ok": True},
                                                                             **result), source=self.source(runner))

    def once(self, t, lines=None, **result):
        """One scheduled run of trigger t at its next due time, with this result. Returns (answer, run row)."""
        t = hub.trigger_row(t["id"])
        self.tick(t["next_due"])
        runner, extra = self.sent(t["id"])
        self.assertEqual(runner, t["agent"])            # its own machine, and no other
        code, answer = self.post(runner, extra, **({"lines": lines} if lines is not None else result))
        self.assertEqual(code, 200, answer)
        return answer, hub.q1("SELECT * FROM trigger_runs WHERE id=?", (extra["run"],))

    def model_events(self):
        return hub.q1("SELECT COUNT(*) n FROM events WHERE id>? AND kind IN ('say','task','chat')", (self.first_event,))["n"]

    def new_tasks(self):
        return hub.q("SELECT * FROM tasks WHERE id>? ORDER BY id", (self.first_task,))

    def end(self, task_id, state="completed"):
        hub.q("UPDATE tasks SET state=?, delivered=?, accepted=1 WHERE id=?", (state, self.clock, task_id))

    # ---- the tests of plan P4

    def test_the_hubs_event_and_the_real_runner_agree_from_end_to_end(self):
        """The hub's own check event, the real runner of the helper (it fetches the code from the hub's route of the
        open claim) with the agent's keys, and its result posted back: the agent wakes with what the code printed."""
        code = ("import json, os, sys\nargs = json.loads(sys.argv[1])['args']\n"
                "for n in args['tickets']:\n    print(f'T-{n} new, key {os.environ[\"SHOP_KEY\"][:2]}')\n")
        t = self.save("vps", "req-e2e-0001", check={"code": code, "args": {"tickets": [81, 82]}})
        self.tick(t["next_due"])
        runner, extra = self.sent(t["id"])
        source = self.source(runner)
        # DevOps plan 0.2: the agent's own session put the code in its machine's store; the hub sends the SHA-256
        store = Path(tempfile.mkdtemp(prefix="fleet-checks-"))
        self.addCleanup(shutil.rmtree, str(store), True)
        (store / f"{extra['sha256']}.py").write_text(code)
        self.assertNotIn("source", extra)
        with patch.object(fleet, "http", side_effect=AssertionError("a saved check asks the hub for nothing")):
            result = fleet.run_check(extra, agent=runner, keys={"SHOP_KEY": "k-vps"}, store=str(store))
        self.assertEqual(result["lines"], ["T-81 new, key k-", "T-82 new, key k-"])
        code, answer = self.request(f"/helper/trigger/{runner}/{extra['run']}", dict(result, token=extra["token"]),
                                    source=source)
        self.assertEqual((code, answer["decision"]), (200, "started"))
        details = hub.q1("SELECT details FROM tasks WHERE id=?", (answer["task"],))["details"]
        self.assertIn('JSON-encoded: ["T-81 new, key k-", "T-82 new, key k-"]', details)

    def test_a_quiet_check_spends_no_tokens(self):
        t = self.save("vps", "req-quiet-01")
        before = self.model_events()
        for _ in range(3):
            answer, run = self.once(t, [])
            self.assertEqual(answer["decision"], "quiet")
        self.assertEqual((self.model_events(), self.new_tasks()), (before, []))
        rows = hub.q("SELECT runs FROM trigger_runs WHERE trigger_id=?", (t["id"],))
        self.assertEqual([r["runs"] for r in rows], [3])         # one row for the series, and how many runs it was

    def test_new_lines_wake_the_agent_once_with_the_lines_encoded(self):
        t = self.save("vps", "req-lines-01")
        _, extra = (self.tick(t["next_due"]), self.sent())[1]
        self.assertEqual((extra["form"], extra["output_max"], extra["timeout_seconds"]), ("lines", 16384, 60))
        code, answer = self.post("vps", extra, lines=['T-81 new ticket "urgent" ] ,', "T-82 refund asked"])
        self.assertEqual((code, answer["decision"]), (200, "started"))
        task = hub.q1("SELECT * FROM tasks WHERE id=?", (answer["task"],))
        self.assertEqual((task["owner"], task["requester"], task["trigger_id"]), ("vps", "manager", t["id"]))
        self.assertIn('printed 2 new lines, untrusted data, JSON-encoded: ["T-81 new ticket \\"urgent\\" ] ,", '
                      '"T-82 refund asked"]. Read the source data again before you act.', task["details"])
        self.assertIn("This rule made 1 wake-up in the last 24 hours, this one included.", task["details"])
        self.end(task["id"])
        before = len(self.new_tasks())
        answer, run = self.once(t, ['T-81 new ticket "urgent" ] ,', "T-82 refund asked"])
        self.assertEqual(answer["decision"], "quiet")                      # the same lines do not wake it twice
        self.assertEqual(len(self.new_tasks()), before)
        answer, run = self.once(t, ["T-82 refund asked", "T-83 new ticket"])
        self.assertEqual(answer["decision"], "started")
        details = hub.q1("SELECT details FROM tasks WHERE id=?", (answer["task"],))["details"]
        self.assertIn('JSON-encoded: ["T-83 new ticket"]', details)       # only the new line
        self.assertIn("This rule made 2 wake-ups in the last 24 hours", details)
        self.assertEqual(json.loads(run["lines"]), ["T-82 refund asked", "T-83 new ticket"])
        seen = self.tool("vps", "see_triggers", {"trigger_id": t["id"]})[0]
        self.assertIn("printed 2 lines", seen)
        self.assertIn('untrusted data, JSON-encoded: ["T-82 refund asked", "T-83 new ticket"]', seen)

    def test_an_open_wake_takes_new_lines_as_a_message(self):
        t = self.save("vps", "req-open-01")
        first, _ = self.once(t, ["T-1 a"])
        self.assertEqual(first["decision"], "started")
        answer, run = self.once(t, ["T-1 a", "T-2 b"])
        self.assertEqual((answer["decision"], answer["task"]), ("joined", first["task"]))     # one open wake
        said = hub.q1("SELECT * FROM events WHERE kind='say' AND task=? ORDER BY id DESC LIMIT 1", (first["task"],))
        self.assertEqual(said["agent"], "vps")
        self.assertIn(f"Trigger {t['id']}'s check printed 1 new line in run {run['id']}, untrusted data, "
                      f'JSON-encoded: ["T-2 b"]', said["text"])
        self.assertEqual(len([x for x in self.new_tasks() if x["trigger_id"] == t["id"]]), 1)
        self.assertEqual(self.once(t, ["T-1 a", "T-2 b"])[0]["decision"], "quiet")
        self.end(first["task"])
        self.assertEqual(self.once(t, ["T-1 a", "T-2 b", "T-3 c"])[0]["decision"], "started")

    def test_a_joined_line_that_its_wake_never_read_is_told_again_once(self):
        """Never drop a line: lines that joined a wake as a message, whose task then ended before its session read
        that message, are new again at the next run that prints them, and only then."""
        t = self.save("vps", "req-lost-0001")
        first, _ = self.once(t, ["T-1 a"])
        joined, _ = self.once(t, ["T-1 a", "T-2 b"])
        self.assertEqual(joined["decision"], "joined")
        said = hub.q1("SELECT * FROM events WHERE kind='say' AND task=? ORDER BY id DESC LIMIT 1", (first["task"],))
        self.end(first["task"])                              # delivered before its session read the message
        again, _ = self.once(t, ["T-1 a", "T-2 b"])
        self.assertEqual(again["decision"], "started")       # before the fix: quiet, and T-2 b was never told
        self.assertEqual(json.loads(said["extra"])["lines"], ["T-2 b"])
        details = hub.q1("SELECT details FROM tasks WHERE id=?", (again["task"],))["details"]
        self.assertIn('JSON-encoded: ["T-2 b"]', details)    # only the lost line
        self.assertEqual(json.loads(hub.q1("SELECT extra FROM events WHERE id=?", (said["id"],))["extra"])["resent"],
                         hub.q1("SELECT MAX(id) m FROM trigger_runs WHERE trigger_id=?", (t["id"],))["m"])
        self.end(again["task"])
        self.assertEqual(self.once(t, ["T-1 a", "T-2 b"])[0]["decision"], "quiet")      # and once
        # a line message that its session read is delivered, whatever happens to its task after
        read, _ = self.once(t, ["T-1 a", "T-2 b", "T-3 c"])
        self.once(t, ["T-1 a", "T-2 b", "T-3 c", "T-4 d"])
        hub.q("UPDATE events SET read_at=? WHERE kind='say' AND task=?", (self.clock, read["task"]))
        self.end(read["task"])
        self.assertEqual(self.once(t, ["T-1 a", "T-2 b", "T-3 c", "T-4 d"])[0]["decision"], "quiet")

    def test_the_fleet_managers_open_wake_message_takes_new_lines(self):
        t = self.save("manager", "req-mgr-01")
        first, run = self.once(t, ["G-1 off track"])
        self.assertEqual(first["decision"], "started")
        event = run["event_id"]
        answer, run = self.once(t, ["G-1 off track", "G-2 late"])
        self.assertEqual((answer["decision"], run["event_id"]), ("joined", event))
        text = hub.q1("SELECT text FROM events WHERE id=?", (event,))["text"]
        self.assertIn('JSON-encoded: ["G-1 off track"]', text)
        self.assertIn('JSON-encoded: ["G-2 late"]', text)
        hub.q("UPDATE events SET read_at=? WHERE id=?", (self.clock, event))
        self.assertEqual(self.once(t, ["G-1 off track", "G-2 late", "G-3 new"])[0]["decision"], "started")

    def test_a_crash_a_timeout_and_an_edit_lose_no_line(self):
        t = self.save("vps", "req-crash-01")
        for error in ("exit", "timeout"):                   # its process dies, or runs too long
            answer, run = self.once(t, ok=False, error=error, detail="x", tail="Traceback: boom")
            self.assertEqual(answer["decision"], "error")
        answer, _ = self.once(t, ["T-1 a"])
        self.assertEqual(answer["decision"], "started")     # the line that the failed runs never delivered
        self.end(answer["task"])
        open_run = hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,state,created,retry_at) VALUES(?,?,?,"
                           "'waiting',?,?)", (t["id"], t["revision"], self.clock + 1, self.clock, self.clock + 9999))
        t = hub.trigger_row(t["id"])
        text, error = self.tool("vps", "save_trigger", {"request_id": "req-crash-02", "trigger_id": t["id"],
                                                        "base_revision": t["revision"],
                                                        "task": dict(TASK, title="New and old tickets")})
        self.assertFalse(error, text)
        self.assertEqual(hub.q1("SELECT state FROM trigger_runs WHERE id=?", (open_run,))["state"], "obsolete")
        answer, _ = self.once(t, ["T-1 a", "T-2 b"])
        self.assertEqual(answer["decision"], "started")
        details = hub.q1("SELECT details FROM tasks WHERE id=?", (answer["task"],))["details"]
        self.assertIn('JSON-encoded: ["T-2 b"]', details)  # T-1 was told before the edit, and only once

    def test_lines_behind_a_usage_limit_wait_with_their_run(self):
        t = self.save("vps", "req-limit-01")
        until = self.clock + 5000
        limit = hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('vps',?,?,1)", (self.clock, until))
        answer, run = self.once(t, ["T-1 a", "T-2 b"])
        self.assertEqual(answer["decision"], "waiting")
        held = hub.q1("SELECT * FROM trigger_runs WHERE id=?", (run["id"],))
        self.assertEqual((held["state"], held["retry_at"], json.loads(held["lines"])), ("waiting", until, ["T-1 a", "T-2 b"]))
        checks = hub.q1("SELECT COUNT(*) n FROM events WHERE kind='trigger_check'")["n"]
        t = hub.trigger_row(t["id"])
        self.tick(t["next_due"])                             # a newer due time does not replace a run that holds lines
        self.assertEqual(hub.q1("SELECT state FROM trigger_runs WHERE id=?", (run["id"],))["state"], "waiting")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM trigger_runs WHERE trigger_id=?", (t["id"],))["n"], 1)
        self.assertEqual(self.new_tasks(), [])
        hub.q("UPDATE agent_limits SET ended=? WHERE id=?", (until, limit))
        self.tick(until)                                     # the limit ends: its own lines, no new execution
        held = hub.q1("SELECT * FROM trigger_runs WHERE id=?", (run["id"],))
        self.assertEqual(held["state"], "started")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE kind='trigger_check'")["n"], checks)
        details = hub.q1("SELECT details FROM tasks WHERE id=?", (held["task"],))["details"]
        self.assertIn('JSON-encoded: ["T-1 a", "T-2 b"]', details)
        self.end(held["task"])
        self.assertEqual(self.once(t, ["T-1 a", "T-2 b"])[0]["decision"], "quiet")     # and told once

    def test_the_third_failure_wakes_once_with_the_error_tail(self):
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
                ("practice", "s1", hashlib.sha256(("s1" + SECRET).encode()).hexdigest(), len(SECRET), "u"))
        t = self.save("vps", "req-fail-01")
        tail = f'Traceback (most recent call last):\n  File "<check>", line 3\nKeyError: "{SECRET}" quote"'
        for n in (1, 2):
            self.assertEqual(self.once(t, ok=False, error="exit", detail="exit code 1", tail=tail)[0]["task"], None)
        answer, run = self.once(t, ok=False, error="exit", detail="exit code 1", tail=tail)
        fix = hub.q1("SELECT * FROM tasks WHERE id=?", (answer["task"],))
        self.assertEqual((answer["decision"], fix["owner"], fix["trigger_id"]), ("error", "vps", t["id"]))
        self.assertIn(f"The check of trigger {t['id']} (New tickets) failed 3 times in a row", fix["details"])
        self.assertIn("KeyError", fix["details"])
        self.assertIn('\\"', fix["details"])                 # the tail is JSON-encoded
        self.assertNotIn(SECRET, fix["details"])             # and masked
        self.assertEqual(self.once(t, ok=False, error="exit", detail="exit code 1")[0]["task"], None)  # once
        self.assertEqual(len(self.new_tasks()), 1)
        self.end(fix["id"])
        self.assertEqual(self.once(t, [])[0]["decision"], "quiet")               # a valid run ends the series
        for n in (1, 2, 3):
            answer, _ = self.once(t, ok=False, error="exit", detail="again")
        self.assertIsNotNone(answer["task"])                                    # a new series wakes again
        self.assertEqual(len(self.new_tasks()), 2)
        line = hub.checks_start_text("vps", self.new_tasks()[-1]["id"])
        self.assertIn("fails since", line)

    def test_a_lead_under_several_waking_workers_gets_one_check_task(self):
        """Plan P9.11: the wake-ups of a lead's team are subtasks of one task of the lead, not one each."""
        seo = self.save("seo", "req-seo-0001")
        dev = self.save("dev", "req-dev-0001")
        a, _ = self.once(seo, ["T-1 seo"])
        b, _ = self.once(dev, ["T-2 dev"])
        c, _ = self.once(seo, ["T-1 seo", "T-3 seo"])        # joins seo's open wake
        lead = [x for x in self.new_tasks() if x["owner"] == "lead"]
        self.assertEqual(len(lead), 1)
        self.assertEqual((lead[0]["requester"], lead[0]["title"]), ("manager", "Your team's wake-up and case results"))
        children = hub.q("SELECT * FROM tasks WHERE parent=? ORDER BY id", (lead[0]["id"],))
        self.assertEqual([(x["owner"], x["requester"]) for x in children], [("seo", "lead"), ("dev", "lead")])
        self.assertEqual((c["decision"], c["task"]), ("joined", a["task"]))
        runs = hub.q("SELECT parent_task FROM trigger_runs WHERE state='started' ORDER BY id")
        self.assertEqual({r["parent_task"] for r in runs}, {lead[0]["id"]})
        # the duty review of a worker under the lead joins the same task
        with hub.transaction():
            hub.duty_review_rows("seo", w.wake_route(hub.wake_org(), "seo")[0], ["R-1 new"], self.clock)
        self.assertEqual(len([x for x in self.new_tasks() if x["owner"] == "lead"]), 1)
        # the lead delivers it; the next wake-up gets a new one
        for x in hub.q("SELECT id FROM tasks WHERE parent=?", (lead[0]["id"],)):
            self.end(x["id"])
        self.end(lead[0]["id"])
        d, _ = self.once(dev, ["T-2 dev", "T-4 dev"])
        self.assertEqual(d["decision"], "started")
        lead = [x for x in self.new_tasks() if x["owner"] == "lead"]
        self.assertEqual(len(lead), 2)
        self.assertEqual(hub.q1("SELECT parent FROM tasks WHERE id=?", (d["task"],))["parent"], lead[1]["id"])

    def test_the_progress_line_records_the_target_and_wakes_nobody(self):
        t = self.save("vps", "req-prog-01")
        target = hub.ins("INSERT INTO standing(agent,scope,kind,words,measure,number,due,how,\"check\",author_kind,"
                         "author,created) VALUES('vps','agent','target','first drafts within 2 hours','percent',90,?,"
                         "'the CRM',?,'agent','vps',?)", (self.clock + 86400 * 30, t["id"], self.clock))
        answer, run = self.once(t, ["progress 87"])
        self.assertEqual(answer["decision"], "quiet")
        self.assertEqual(hub.q1("SELECT progress FROM standing WHERE id=?", (target,))["progress"], 87)
        self.assertEqual(json.loads(run["lines"]), [])
        answer, _ = self.once(t, ["progress 80", "T-9 off track: 80 of 90"])
        self.assertEqual(answer["decision"], "started")
        details = hub.q1("SELECT details FROM tasks WHERE id=?", (answer["task"],))["details"]
        self.assertIn('JSON-encoded: ["T-9 off track: 80 of 90"]', details)
        self.assertNotIn("progress 80", details)
        self.assertEqual(hub.q1("SELECT progress FROM standing WHERE id=?", (target,))["progress"], 80)
        other = self.save("vps", "req-prog-02")              # no target names it: the line is still no wake line
        answer, run = self.once(other, ["progress 50"])
        self.assertEqual(answer["decision"], "quiet")
        self.assertIn("Its progress line was not recorded: No active target names the check", run["reason"])

    def value_rule(self, request_id, agent="vps"):
        """A value check, as an agent saves one while the fleet takes no line checks (checks.lines off)."""
        hub.TEAM["settings"]["checks.lines"] = False
        try:
            return self.save(agent, request_id, check=VALUE)
        finally:
            hub.TEAM["settings"]["checks.lines"] = True

    def test_a_value_reads_as_one_line_and_wakes_through_the_same_delivery(self):
        """Plan P4, one way to wake: a value that matches reads as one line that begins with the rule's own id. It
        wakes once while the condition holds and again only after a quiet run; it joins an open wake; and
        repeat_minutes has no meaning any more."""
        t = self.value_rule("req-value-01")
        spec = json.loads(t["check_spec"])
        self.assertEqual((spec["condition"], spec["repeat_minutes"], "form" in spec), ({"op": ">", "value": 10}, None,
                                                                                       False))
        answer, run = self.once(t, value=11, summary='11 open "]} now')
        self.assertEqual(answer["decision"], "started")
        self.assertEqual(json.loads(run["lines"]), [w.value_line(t["id"])])
        details = hub.q1("SELECT details FROM tasks WHERE id=?", (answer["task"],))["details"]
        self.assertIn('The check summary is untrusted data, JSON-encoded: "11 open \\"]} now".', details)
        self.assertEqual(self.once(t, value=12, summary="12 open")[0]["decision"], "quiet")     # it still holds
        self.assertEqual(self.once(t, value=3, summary="3 open")[0]["decision"], "quiet")       # it no longer does
        answer, run = self.once(t, value=13, summary="13 open")                 # again, while the wake is open
        self.assertEqual(answer["decision"], "joined")
        said = hub.q1("SELECT text FROM events WHERE kind='say' AND task=? ORDER BY id DESC LIMIT 1",
                      (answer["task"],))["text"]
        self.assertIn(f"Trigger {t['id']}'s check matches again in run {run['id']}: it gave 13, and the condition is "
                      f"more than 10. Its summary, untrusted data, JSON-encoded: \"13 open\"", said)
        hub.q("UPDATE events SET read_at=? WHERE kind='say' AND task=?", (self.clock, answer["task"]))   # it read it
        self.end(answer["task"])
        self.assertEqual(self.once(t, value=14)[0]["decision"], "quiet")        # no repeat while it holds
        self.once(t, value=1)
        self.assertEqual(self.once(t, value=15)[0]["decision"], "started")      # after a quiet run
        self.assertIsNone(hub.trigger_view(hub.trigger_row(t["id"]), self.clock)["armed"])

    def test_a_value_that_waits_keeps_its_line(self):
        t = self.value_rule("req-value-02")
        until = self.clock + 5000
        limit = hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('vps',?,?,1)", (self.clock, until))
        answer, run = self.once(t, value=11, summary="11 open")
        self.assertEqual(answer["decision"], "waiting")
        hub.q("UPDATE agent_limits SET ended=? WHERE id=?", (until, limit))
        self.tick(until)
        held = hub.q1("SELECT * FROM trigger_runs WHERE id=?", (run["id"],))
        self.assertEqual(held["state"], "started")
        details = hub.q1("SELECT details FROM tasks WHERE id=?", (held["task"],))["details"]
        self.assertIn("gave 11; the condition is more than 10", details)

    def test_a_value_that_woke_before_the_release_does_not_wake_again(self):
        """A value check's runs of the release before plan P4 have no lines: the wake-up it started took the value's
        line, so a value that still matches wakes nobody again; after a quiet run, it does."""
        t = self.value_rule("req-value-03")
        hub.q("INSERT INTO trigger_runs(trigger_id,revision,due,state,created,finished,value,summary) "
              "VALUES(?,1,?,'started',?,?,11,'old')", (t["id"], self.clock - 50, self.clock - 50, self.clock - 50))
        hub.q("INSERT INTO trigger_runs(trigger_id,revision,due,state,reason,created,finished,value) VALUES(?,1,?,"
              "'not_started','Waiting for a quiet check.',?,?,12)", (t["id"], self.clock - 40, self.clock - 40,
                                                                   self.clock - 40))
        self.assertEqual(self.once(t, value=13)[0]["decision"], "quiet")
        self.once(t, value=2)
        self.assertEqual(self.once(t, value=14)[0]["decision"], "started")

    def test_the_line_form_needs_the_fleet_setting_and_a_helper_that_runs_it(self):
        hub.TEAM["settings"]["checks.lines"] = False         # the shipped app cannot read such a rule
        text, error = self.tool("vps", "save_trigger", {"request_id": "req-gate-01", "schedule": EVERY, "task": TASK,
                                                        "check": LINES})
        self.assertTrue(error)
        self.assertIn("This fleet does not take checks that print lines yet. Give the check a condition", text)
        self.assertNotIn("repeat_minutes", text)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM triggers")["n"], 0)
        value = self.save("vps", "req-gate-02", check=VALUE)  # old checks keep working all the time
        self.assertEqual(self.once(value, value=1)[0]["decision"], "quiet")
        hub.TEAM["settings"]["checks.lines"] = True
        text, error = self.tool("vps", "save_trigger", {"request_id": "req-gate-04", "schedule": EVERY, "task": TASK,
                                                        "check": VALUE})
        self.assertTrue(error)                               # one way to wake once the fleet takes lines
        self.assertIn("Checks print lines in this fleet: leave out condition", text)
        value = hub.trigger_row(value["id"])                 # an edit that keeps its check is no new value check
        text, error = self.tool("vps", "save_trigger", {"request_id": "req-gate-05", "trigger_id": value["id"],
                                                        "base_revision": value["revision"],
                                                        "task": dict(TASK, title="Old tickets")})
        self.assertFalse(error, text)
        t = self.save("vps", "req-gate-03")
        helper_reports("vps", "trigger_check", "trigger_code")     # an older helper: no check_lines
        t = hub.trigger_row(t["id"])
        self.tick(t["next_due"])
        run = hub.q1("SELECT * FROM trigger_runs WHERE trigger_id=? ORDER BY id DESC LIMIT 1", (t["id"],))
        self.assertEqual(run["state"], "waiting")
        self.assertEqual("Vps cannot run this check yet. Update Founderizer on its server.", run["reason"])
        helper_reports("vps", *FEATURES)
        self.tick(self.clock + 1)
        self.assertEqual(hub.q1("SELECT state FROM trigger_runs WHERE id=?", (run["id"],))["state"], "sent")
        self.assertIn("check_lines", lifecycle.FEATURES)

    def test_a_target_takes_only_a_check_that_prints_lines(self):
        """AUTONOMY.md 6.5: only a check that prints lines records progress, so a target takes no other check, and
        while the fleet takes no line checks the agent gives a target's progress itself."""
        lines = self.save("vps", "req-target-01")
        value = self.value_rule("req-target-02")
        target = {"measure": "tickets answered within a day, in percent", "number": 90, "how": "the ticket system",
                  "scope": "agent"}
        text, error = self.tool("vps", "set_target", dict(target, check=value["id"]))
        self.assertTrue(error)
        self.assertIn(f"Wake-up rule {value['id']}'s check does not print lines, so it records no progress", text)
        self.assertNotIn("This fleet does not take such checks yet", text)
        text, error = self.tool("vps", "set_target", dict(target, check=lines["id"]))
        self.assertFalse(error, text)
        hub.TEAM["settings"]["checks.lines"] = False
        text, error = self.tool("vps", "set_target", dict(target, measure="refunds answered, in percent",
                                                          check=value["id"]))
        self.assertIn("This fleet does not take such checks yet: leave check out, and give the target's progress "
                      "yourself with progress.", text)
        text, error = self.tool("vps", "set_target", dict(target, measure="refunds answered, in percent", progress=40))
        self.assertFalse(error, text)

    def test_the_fleet_managers_brief_lists_the_new_checks_of_the_agents_that_report_to_it(self):
        """Plan P4: a lead reads its team's new and changed checks in its sessions' starts; the fleet manager reads
        those of the agents that report to it in its brief, since its last brief."""
        hub.TEAM["agents"]["lead"]["role"] = "lead"
        first = hub.manager_resume_text()                   # its first brief: nothing yet
        self.assertNotIn("CHECKS", first)
        self.clock += 60
        own = self.save("manager", "req-brief-01")
        vps = self.save("vps", "req-brief-02")
        seo = self.save("seo", "req-brief-03")              # under a lead: the lead reads it, not the brief
        self.clock += 60
        brief = hub.manager_resume_text()
        self.assertIn("YOUR CHECKS", brief)
        self.assertIn(f"- Trigger {own['id']} (NEW", brief)
        self.assertIn("NEW OR CHANGED CHECKS OF THE AGENTS THAT REPORT TO YOU since your last brief", brief)
        self.assertIn(f"- Trigger {vps['id']} of vps (NEW, by vps in {self.sessions['vps'][1]})", brief)
        self.assertNotIn(f"Trigger {seo['id']} of seo", brief)
        self.assertLess(brief.index("YOUR CHECKS"), brief.index("Then call read_messages"))     # before the receipt
        self.clock += 60
        again = hub.manager_resume_text()                   # told once
        self.assertNotIn("NEW OR CHANGED CHECKS", again)
        self.assertIn(f"- Trigger {own['id']}: New tickets", again)

    def test_a_check_runs_only_on_its_own_agents_machine(self):
        text, error = self.tool("manager", "save_trigger", {"request_id": "req-own-0001", "schedule": EVERY,
                                                            "task": TASK, "agent": "vps",
                                                            "check": dict(LINES, run_on="seo")})
        self.assertTrue(error)
        self.assertIn("check has no field run_on", text)
        t = self.save("vps", "req-own-0002")
        self.tick(t["next_due"])
        self.assertEqual(self.sent()[0], "vps")
        old = self.value_rule("req-own-0003")               # stored before plan P4, for seo:
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(dict(json.loads(old["check_spec"]),
                                                                              run_on="seo")), old["id"]))
        old = hub.trigger_row(old["id"])
        self.tick(old["next_due"])
        row = hub.trigger_row(old["id"])
        self.assertEqual((row["state"], row["paused_by"]), ("paused", "hub"))
        self.assertIn("saved to run on seo's machine", row["paused_reason"])
        self.assertEqual(hub.q("SELECT * FROM events WHERE kind='trigger_check' AND agent='seo'"), [])

    def test_another_agents_code_never_runs_with_an_agents_keys(self):
        """Review defect 2: a check runs with its agent's read keys, so only that agent saves its code; the fleet
        manager's code on a worker's rule would run with the worker's keys. The manager still sets any agent a
        wake-up without a check, and runs checks of its own."""
        text, error = self.tool("manager", "save_trigger", {"request_id": "req-keys-0001", "schedule": EVERY,
                                                            "task": TASK, "agent": "vps", "check": LINES})
        self.assertTrue(error)
        self.assertIn("A check runs only with code that its own agent saved, and manager saved this one: only vps "
                      "saves the code of vps's checks.", text)
        prompt = self.save("manager", "req-keys-0002", agent="vps", check=None)      # a wake-up without a check
        self.assertIsNone(prompt["check_spec"])
        own = self.save("manager", "req-keys-0003")                                    # the manager's own check
        self.tick(own["next_due"])
        self.assertEqual(self.sent(own["id"])[0], "manager")
        mine = self.save("vps", "req-keys-0004")              # vps's own check: the manager cannot change its code
        text, error = self.tool("manager", "save_trigger", {"request_id": "req-keys-0005", "trigger_id": mine["id"],
                                                            "base_revision": mine["revision"],
                                                            "check": {"code": "print('T-1')"}})
        self.assertTrue(error)
        self.assertIn("only vps saves the code of vps's checks", text)
        # a rule that a release before this one stored with the manager's code: it stops, and runs nothing
        theirs = self.save("vps", "req-keys-0006")
        spec = dict(json.loads(theirs["check_spec"]), code_by="manager")
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(spec), theirs["id"]))
        self.tick(hub.trigger_row(theirs["id"])["next_due"])
        row = hub.trigger_row(theirs["id"])
        self.assertEqual((row["state"], row["paused_by"]), ("paused", "hub"))
        self.assertIn("A check runs only with code that its own agent saved", row["paused_reason"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM events WHERE kind='trigger_check' AND agent='vps' AND "
                                "json_extract(extra, '$.trigger')=?", (theirs["id"],))["n"], 0)

    def test_the_error_output_is_masked_whole_before_it_is_cut(self):
        """Review defect 3: a login that crosses the cut of the error output keeps no unmasked end in the wake."""
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
                ("practice", "s1", hashlib.sha256(("s1" + SECRET).encode()).hexdigest(), len(SECRET), "u"))
        token = "11111111-2222-4333-8444-555555555555"
        crossing = "a" * 100 + SECRET + "b" * (hub.CHECK_TAIL - 6)       # the hub's cut falls 6 before its end
        body = hub.check_body({"token": token, "ok": False, "error": "exit", "detail": "1", "tail": crossing})
        self.assertNotIn(SECRET[-6:], body.get("tail") or "")       # before the fix: cut, then masked
        for at in range(len(SECRET) + 1):                    # the cut falls at every place in the login
            tail = hub.error_tail(("z" * 3000) + "\n" + "x" * (hub.CHECK_TAIL - at - 20) + SECRET + "\nKeyError\n")
            self.assertNotIn(SECRET[-6:], tail, at)
            self.assertNotIn(SECRET[:6], tail, at)
            self.assertLessEqual(len(tail), hub.CHECK_TAIL)
        body = hub.check_body({"token": token, "ok": False, "error": "exit", "detail": "1",
                               "tail": "a" * 5000 + "\n" + SECRET + "\nKeyError: 'x'"})
        self.assertNotIn(SECRET, body["tail"])
        self.assertIn("KeyError", body["tail"])

    def test_both_runtime_forms_run_their_own_line_checks(self):
        """AUTONOMY.md P10: the Claude form (full access) and the Codex form each run their own checks; a runtime
        that asks before commands runs none."""
        for agent in ("seo", "vps"):
            with self.subTest(agent=agent):
                t = self.save(agent, f"req-form-{agent}")
                answer, _ = self.once(t, [f"T-1 {agent}"])
                self.assertEqual(answer["decision"], "started")
        hub.TEAM["agents"]["seo"].update(start="claude --permission-mode acceptEdits {settings} {prompt}", allow=[])
        text, error = self.tool("seo", "save_trigger", {"request_id": "req-form-ask", "schedule": EVERY, "task": TASK,
                                                        "check": LINES})
        self.assertTrue(error)
        self.assertIn("seo cannot run saved code", text)

    def test_the_settings_bound_one_run(self):
        hub.TEAM["settings"].update({"checks.run_seconds": 30, "checks.output_bytes": 4096})
        text, error = self.tool("vps", "save_trigger", {"request_id": "req-set-0001", "schedule": EVERY, "task": TASK,
                                                        "check": dict(LINES, timeout_seconds=45)})
        self.assertTrue(error)
        self.assertIn("check.timeout_seconds", text)
        t = self.save("vps", "req-set-0002")
        self.assertEqual(json.loads(t["check_spec"])["timeout_seconds"], 30)
        self.tick(t["next_due"])
        self.assertEqual((self.sent()[1]["output_max"], self.sent()[1]["timeout_seconds"]), (4096, 30))
        hub.TEAM["settings"]["checks.run_seconds"] = "a lot"      # a value its check refuses reads as the default
        self.assertEqual(hub.setting("checks.run_seconds"), 60)

    def test_check_now_never_wakes_and_accepts_no_line(self):
        t = self.save("vps", "req-now-0001")
        text, error = self.tool("vps", "change_trigger", {"request_id": "req-now-0002", "trigger_id": t["id"],
                                                          "base_revision": t["revision"], "action": "check_now"})
        self.assertFalse(error, text)
        runner, extra = self.sent()
        code, answer = self.post(runner, extra, lines=["T-1 a"])
        self.assertEqual(answer["decision"], "not_started")
        self.assertEqual(self.new_tasks(), [])
        self.assertEqual(self.once(t, ["T-1 a"])[0]["decision"], "started")      # still new for the scheduled run

    def run_now(self, t):
        """The owner's Run task now of trigger t, through his own route."""
        t = hub.trigger_row(t["id"])
        return self.request(f"/ui/triggers/{t['id']}/state", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                                   base_revision=t["revision"], action="run_now"))

    def test_run_now_runs_the_check_and_wakes_only_for_new_lines(self):
        """Owner API 1.83 (4 November 2026: Run now of rule 19 started T-143 with no check): Run task now of an
        agent's rule with a check runs the check once and decides its result as a scheduled run, so only what is new
        wakes the agent and its lines are accepted."""
        t = self.save("vps", "req-run-0001")
        due, events = hub.trigger_row(t["id"])["next_due"], self.model_events()
        code, answer = self.run_now(t)
        self.assertEqual(code, 200, answer)
        row = hub.q1("SELECT * FROM trigger_runs WHERE id=?", (answer["run"]["id"],))
        self.assertEqual((row["state"], row["manual"], row["check_now"], row["attempts"], row["task"]),
                         ("sent", 1, 0, 1, None))
        self.assertEqual((self.new_tasks(), self.model_events()), ([], events))
        self.assertEqual(hub.trigger_row(t["id"])["next_due"], due)          # no setting and no due time moves
        self.assertEqual(self.run_now(t)[0], 409)                            # one run in flight, as for Check now
        runner, extra = self.sent(t["id"])
        code, result = self.post(runner, extra, lines=[])
        self.assertEqual((code, result["decision"]), (200, "quiet"))
        self.assertEqual((self.new_tasks(), self.model_events()), ([], events))
        self.assertEqual(self.run_now(t)[0], 200)
        runner, extra = self.sent(t["id"])
        code, result = self.post(runner, extra, lines=["T-1 a"])
        self.assertEqual((code, result["decision"]), (200, "started"), result)
        task = hub.q1("SELECT * FROM tasks WHERE id=?", (result["task"],))
        self.assertIn("through Run task now at", task["details"])
        self.assertIn('"T-1 a"', task["details"])
        self.end(task["id"])
        self.assertEqual(self.once(t, ["T-1 a"])[0]["decision"], "quiet")     # accepted: its due time finds nothing new

    def test_run_now_leaves_a_one_off_rule_its_time(self):
        once = {"kind": "once", "at": "2026-12-01T09:00", "timezone": "Europe/Madrid"}
        t = self.save("vps", "req-once-0001", schedule=once)
        due = hub.trigger_row(t["id"])["next_due"]
        self.assertEqual(self.run_now(t)[0], 200)
        runner, extra = self.sent(t["id"])
        self.assertEqual(self.post(runner, extra, lines=["T-1 a"])[1]["decision"], "started")
        self.assertEqual((hub.trigger_row(t["id"])["state"], hub.trigger_row(t["id"])["next_due"]), ("active", due))
        self.end(self.new_tasks()[-1]["id"])
        self.assertEqual(self.once(t, ["T-1 a", "T-2 b"])[0]["decision"], "started")     # its own time, then done
        self.assertEqual(hub.trigger_row(t["id"])["state"], "done")

    def test_run_now_of_a_rule_without_a_check_starts_its_task(self):
        text, error = self.tool("vps", "save_trigger", {"request_id": "req-plain-001", "schedule": EVERY, "task": TASK})
        self.assertFalse(error, text)
        t = hub.q1("SELECT * FROM triggers ORDER BY id DESC LIMIT 1")
        code, answer = self.run_now(t)
        self.assertEqual(code, 200, answer)
        self.assertEqual(answer["run"]["state"], "started", answer["run"])           # owner API 1.7, unchanged
        self.assertEqual(len(self.new_tasks()), 1)

    def test_provenance_is_stored_with_each_saved_revision(self):
        t = self.save("vps", "req-prov-0001")
        row = hub.q1("SELECT * FROM trigger_history WHERE trigger_id=? ORDER BY id DESC LIMIT 1", (t["id"],))
        fixture = hub.parse_task(self.sessions["vps"][1])
        self.assertEqual((row["saved_by_task"], row["outside_reads"]), (fixture, 0))
        answer, _ = self.once(t, ["T-1 a"])                  # a wake task reads a wake text: outside text
        wake = (hub.kv_get("db_id"), hub.tref(answer["task"]), 1)
        self.once(t, ["T-1 a", "T-2 b"])                     # and the lines that join it
        t = hub.trigger_row(t["id"])
        text, error = self.tool("vps", "save_trigger", {"request_id": "req-prov-0002", "trigger_id": t["id"],
                                                        "base_revision": t["revision"], "check": {"code": "print(1)"}},
                                context=wake)
        self.assertFalse(error, text)
        row = hub.q1("SELECT * FROM trigger_history WHERE trigger_id=? ORDER BY id DESC LIMIT 1", (t["id"],))
        self.assertEqual((row["action"], row["saved_by_task"], row["outside_reads"]), ("edit", answer["task"], 2))
        self.assertEqual(hub.save_provenance("manager"), (None, None))       # no standing session: not known

    def test_the_start_text_lists_and_marks_new_checks(self):
        self.clock += 60                                    # a minute into the session that saves it
        t = self.save("seo", "req-start-001")
        self.clock += 60
        lead = hub.parse_task(self.open_session("lead")[1])        # the lead's first session after the save
        text = hub.checks_start_text("lead", lead)
        self.assertIn("NEW OR CHANGED CHECKS OF YOUR TEAM", text)
        self.assertIn(f"- Trigger {t['id']} of seo (NEW, by seo in {self.sessions['seo'][1]}): New tickets", text)
        self.assertEqual(hub.checks_start_text("lead", hub.parse_task(self.open_session("lead")[1])), "")  # told once
        self.once(t, ["T-1 a"])
        task = [x for x in self.new_tasks() if x["owner"] == "seo"][-1]["id"]
        text = hub.checks_start_text("seo", task)
        self.assertIn("YOUR CHECKS", text)
        self.assertIn(f"- Trigger {t['id']} (NEW, by seo in {self.sessions['seo'][1]}): New tickets; every 15 "
                      f"minutes; last run", text)
        self.assertIn(f"last wake-up {hub.tref(task)}", text)
        self.assertIn(text.strip(), hub.start_text("seo", task))           # slot 5 of the per-task block
        later = self.open_session("seo")                   # a later session: the check is no longer new
        self.assertNotIn("NEW", hub.checks_start_text("seo", hub.parse_task(later[1])))
        self.assertEqual(hub.checks_start_text("vps", hub.parse_task(self.sessions["vps"][1])), "")


class Runner(unittest.TestCase):
    """The helper's side of plan P4: the real runner on stand-in saved code, and the keys it keeps."""

    def run_saved(self, source, keys=None, **changes):
        """A saved check as the helper runs it (DevOps plan 0.2): from this machine's own store, by its SHA-256,
        which the agent's session wrote, and never from the hub."""
        extra = dict({"trigger": 3, "run": 21, "token": str(uuid.uuid4()), "code": "saved", "form": "lines",
                      "sha256": hashlib.sha256(source.encode()).hexdigest(), "args": {}, "timeout_seconds": 5,
                      "output_max": 1024}, **changes)
        store = Path(tempfile.mkdtemp(prefix="fleet-checks-"))
        self.addCleanup(shutil.rmtree, str(store), True)
        (store / f"{extra['sha256']}.py").write_bytes(source.encode())
        with patch.object(fleet, "http", side_effect=AssertionError("a saved check asks the hub for nothing")):
            return fleet.run_check(extra, agent="vps", keys=keys, store=str(store))

    def test_a_saved_check_runs_only_from_this_machines_own_store(self):
        """DevOps plan 0.2: the hub gives only the SHA-256. A check that is not in the store, or whose file there has
        other bytes, does not run, and the hub is never asked for its code."""
        source = "print('T-1 a')\n"
        sha = hashlib.sha256(source.encode()).hexdigest()
        store = Path(tempfile.mkdtemp(prefix="fleet-checks-"))
        self.addCleanup(shutil.rmtree, str(store), True)
        extra = {"trigger": 3, "run": 21, "token": "t", "code": "saved", "form": "lines", "sha256": sha, "args": {},
                 "timeout_seconds": 5, "output_max": 1024}
        with patch.object(fleet, "http", side_effect=AssertionError("a saved check asks the hub for nothing")):
            self.assertEqual(fleet.run_check(extra, agent="vps", store=str(store))["error"], "missing")
            (store / f"{sha}.py").write_text("print('something else')\n")
            self.assertEqual(fleet.run_check(extra, agent="vps", store=str(store))["error"], "changed")
            (store / f"{sha}.py").write_text(source)
            self.assertEqual(fleet.run_check(extra, agent="vps", store=str(store))["lines"], ["T-1 a"])

    def test_the_store_is_a_folder_that_sessions_may_write_and_the_first_store_stays(self):
        """3 November 2026: Fleet's deny list keeps every session out of ~/.fleet, which holds the agent's key, so no
        agent could put a check in ~/.fleet/checks/. The store is ~/fleet-checks/, which no deny rule names, and a check
        that is still in the first store keeps running."""
        source = "print('T-1 a')\n"
        sha = hashlib.sha256(source.encode()).hexdigest()
        home = Path(tempfile.mkdtemp(prefix="fleet-home-"))
        self.addCleanup(shutil.rmtree, str(home), True)
        new, first = (Path(store) for store in lifecycle.check_stores(str(home)))
        self.assertEqual((new, first), (home / "fleet-checks", home / ".fleet" / "checks"))
        written = f"~/fleet-checks/{sha}.py"
        for rule in fleet.DENY:
            tool, _, pattern = rule.partition("(")
            self.assertFalse(fnmatch.fnmatch(f"cat > {written}" if tool == "Bash" else written, pattern.rstrip(")")),
                             rule)
        extra = {"trigger": 3, "run": 21, "token": "t", "code": "saved", "form": "lines", "sha256": sha, "args": {},
                 "timeout_seconds": 5, "output_max": 1024}
        with patch.dict(os.environ, {"HOME": str(home)}), \
                patch.object(fleet, "http", side_effect=AssertionError("a saved check asks the hub for nothing")):
            missing = fleet.run_check(extra, agent="vps")
            self.assertEqual(missing["error"], "missing")
            self.assertIn(written, missing["detail"])                   # what its agent does about it
            first.mkdir(parents=True)
            (first / f"{sha}.py").write_text(source)
            self.assertEqual(fleet.run_check(extra, agent="vps")["lines"], ["T-1 a"])
            (first / f"{sha}.py").unlink()
            new.mkdir()
            (new / f"{sha}.py").write_text(source)
            self.assertEqual(fleet.run_check(extra, agent="vps")["lines"], ["T-1 a"])

    def test_a_link_or_a_fifo_in_the_store_is_never_read(self):
        """The sessions write the store, so the helper reads a plain file there and nothing else: no link, and no FIFO,
        which would hold a check slot for ever."""
        source = "print('T-1 a')\n"
        sha = hashlib.sha256(source.encode()).hexdigest()
        store = Path(tempfile.mkdtemp(prefix="fleet-checks-"))
        self.addCleanup(shutil.rmtree, str(store), True)
        (store / "real.py").write_text(source)
        extra = {"trigger": 3, "run": 21, "token": "t", "code": "saved", "form": "lines", "sha256": sha, "args": {},
                 "timeout_seconds": 5, "output_max": 1024}
        os.symlink(store / "real.py", store / f"{sha}.py")
        self.assertEqual(fleet.run_check(extra, agent="vps", store=str(store))["error"], "missing")
        (store / f"{sha}.py").unlink()
        os.mkfifo(store / f"{sha}.py")
        self.assertEqual(fleet.run_check(extra, agent="vps", store=str(store))["error"], "changed")

    def test_a_check_prints_lines_and_nothing_is_quiet(self):
        result = self.run_saved("print('T-1 a')\nprint()\nprint('  T-2 b  ')\n")
        self.assertEqual((result["ok"], result["lines"]), (True, ["T-1 a", "T-2 b"]))
        self.assertEqual(self.run_saved("pass\n")["lines"], [])            # nothing printed: nothing happens

    def test_a_failure_carries_the_end_of_its_error_output(self):
        result = self.run_saved("import sys\nprint('x' * 10, file=sys.stderr)\nraise KeyError('missing')\n")
        self.assertEqual((result["ok"], result["error"]), (False, "exit"))
        self.assertIn("KeyError: 'missing'", result["tail"])
        self.assertIn("xxxxxxxxxx", result["tail"])
        loud = self.run_saved("import sys\nsys.stderr.write(('e' * 99 + '\\n') * 1000)\nraise SystemExit(2)\n")
        self.assertLessEqual(len(loud["tail"]), fleet.CHECK_TAIL_KEEP)      # only its end, and all of it was read
        self.assertTrue(loud["tail"].startswith("e" * 99))                  # from a line's start
        one = self.run_saved("import sys\nsys.stderr.write('e' * 100000)\nraise SystemExit(2)\n")
        self.assertNotIn("tail", one)       # one long cut line could hold the end of a key: none of it goes
        key = "KEY-" + "k" * 40
        crossing = self.run_saved("import sys\nsys.stderr.write('x' * (%d - 10) + '%s' + '\\nboom\\n')\n"
                                  "raise SystemExit(1)\n" % (fleet.CHECK_TAIL_KEEP, key))
        self.assertEqual(crossing["tail"], "boom")      # the cut fell inside the key: its line goes whole
        big = self.run_saved("print('y' * 2000)\n")
        self.assertEqual((big["ok"], big["error"]), (False, "too_large"))
        slow = self.run_saved("import time\ntime.sleep(5)\n", timeout_seconds=1)
        self.assertEqual(slow["error"], "timeout")

    def test_a_check_gets_its_own_agents_keys_and_nothing_else_of_the_helper(self):
        code = "import os\nprint(os.environ.get('SHOP_KEY', 'none'), os.environ.get('FLEET_SESSION_TOKEN', 'none'))\n"
        with patch.dict(os.environ, {"FLEET_SESSION_TOKEN": "helper-only"}):
            self.assertEqual(self.run_saved(code, keys={"SHOP_KEY": "k-vps"})["lines"], ["k-vps none"])
            self.assertEqual(self.run_saved(code)["lines"], ["none none"])
        home = self.run_saved("import os\nr = os.path.realpath\nprint(r(os.environ['HOME']) == r(os.getcwd()), "
                              "os.listdir('.'))\n")
        self.assertEqual(home["lines"], ["True []"])

    def test_the_helper_keeps_the_keys_and_reads_them_again_after_a_failure_or_a_grant_change(self):
        helper = object.__new__(fleet.Helper)
        helper.agent = "vps"
        helper.check_env, helper.check_env_grants, helper.check_env_lock = None, None, threading.Lock()
        grants = ['{"bws://a": "read"}']
        reads = []
        with patch.object(fleet, "read_env", lambda agent, conf, kind: reads.append((agent, kind)) or {"K": "v"}), \
                patch.object(fleet, "check_grants", lambda agent: grants[0]):
            self.assertEqual(helper.check_keys(), {"K": "v"})
            self.assertEqual(helper.check_keys(), {"K": "v"})
            self.assertEqual(reads, [("vps", "check")])                     # kept in memory, not read at every run
            grants[0] = '{"bws://a": "read", "bws://b": "read"}'
            helper.check_keys()
            self.assertEqual(len(reads), 2)                                 # a grant change reads them again
            ran = []
            helper.post_check = lambda extra, result: ran.append(result)
            helper.end_outside = lambda: None
            CHECK = {"run": 1}
            with patch.object(fleet, "run_check", lambda extra, agent, keys: {"ok": False, "error": "exit"}):
                fleet.CHECK_SLOTS.acquire()
                helper.check_thread(CHECK)
            helper.check_keys()
            self.assertEqual(len(reads), 3)                                 # a failed run reads them again
            with patch.object(fleet, "run_check", lambda extra, agent, keys: {"ok": True, "lines": []}):
                fleet.CHECK_SLOTS.acquire()
                helper.check_thread(CHECK)
            helper.check_keys()
            self.assertEqual(len(reads), 3)
            # The hub's stamp of the agent's keys (the `keys` of a check event) is another one: this machine's vault
            # took a new delivery of a key, as after the owner replaced its value. The kept keys are read again.
            CHECK["keys"] = 7
            with patch.object(fleet, "run_check", lambda extra, agent, keys: {"ok": True, "lines": []}):
                fleet.CHECK_SLOTS.acquire()
                helper.check_thread(CHECK)
                self.assertEqual(len(reads), 4)
                fleet.CHECK_SLOTS.acquire()
                helper.check_thread(CHECK)
            self.assertEqual(len(reads), 4)                                 # the same stamp: kept in memory


if __name__ == "__main__":
    unittest.main()

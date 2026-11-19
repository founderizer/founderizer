"""A wait that ends when the CI of a commit ends (set_reminder ci): the call's checks and its one read, the park, each
end event and each count, the rate limit, a re-run during the wait, a read that GitHub answers 304, a restart of the
hub in the middle, and the thread that survives every fault. In-process hub, temporary Git repositories and a GitHub
stand-in on a local address; no helper, vault, Google or AI call."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import hub
from test_blocked_access import BlockedAccess


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(CiWait(name) for name in CiWait.__dict__ if name.startswith("test_"))


COMMIT = "0123456789abcdef0123456789abcdef01234567"
REPO = "acme/web"           # ops holds it at write (test_blocked_access.TEAM)


def run(rid, name="CI", status="in_progress", conclusion=None, attempt=1):
    return {"id": rid, "run_attempt": attempt, "name": name, "status": status, "conclusion": conclusion}


class StandIn(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        free = hub.LOCK.lock.acquire(blocking=False)        # no GitHub read holds the hub's lock
        if free:
            hub.LOCK.lock.release()
        self.server.seen.append({"path": self.path, "etag": self.headers.get("If-None-Match"),
                                 "auth": self.headers.get("Authorization"), "lock_free": free})
        status, body, headers = self.server.answers.pop(0) if self.server.answers else (500, {}, {})
        data = json.dumps(body).encode() if status != 304 else b""
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Stop(BaseException):
    """Ends the watcher's loop in its test."""


class CiWait(BlockedAccess):
    def setUp(self):
        super().setUp()
        self.github = ThreadingHTTPServer(("127.0.0.1", 0), StandIn)
        self.github.answers, self.github.seen = [], []
        # a short poll: the cleanup's shutdown() waits for the loop's next look, which was up to 0.5 s in each test
        threading.Thread(target=self.github.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.addCleanup(self.github.server_close)
        self.addCleanup(self.github.shutdown)
        hub.CFG["github_api"] = f"http://127.0.0.1:{self.github.server_address[1]}"
        self.addCleanup(hub.CFG.pop, "github_api", None)
        self.tokens = []
        tokens = patch.object(hub, "github_tokens", side_effect=self.give_token)
        tokens.start()
        self.addCleanup(tokens.stop)
        hub.CI_TOKENS.clear()
        self.addCleanup(hub.CI_TOKENS.clear)
        self.task = self.task_for("ops")

    def give_token(self, repos, agent=None):
        self.tokens.append((dict(repos), agent))
        return [{"token": "ghs_standin", "expires_at": None, "access": "read", "repos": list(repos)}], []

    def answer(self, *runs, status=200, etag=None, headers=None):
        self.github.answers.append((status, {"total_count": len(runs), "workflow_runs": list(runs)},
                                    dict(headers or {}, **({"ETag": etag} if etag else {}))))

    def wait(self, **fields):
        args = dict({"note": "Deploy when CI is green.", "ci": {"repo": REPO, "commit": COMMIT}}, **fields)
        return self.call("ops", "set_reminder", args, self.task)

    def row(self):
        r = hub.q1("SELECT * FROM reminders WHERE task=? ORDER BY id DESC LIMIT 1", (self.task,))
        return r, hub.ci_of(r)

    def waiting(self):
        self.answer(run(11))
        text, error = self.wait()
        self.assertFalse(error, text)
        self.assertIn("watches the GitHub Actions runs of 0123456789ab in acme/web", text)
        return self.row()[0]["id"]

    def test_a_read_that_raises_for_one_commit_stops_no_other_commit(self):
        first = self.waiting()
        other_task, other = self.task_for("ops"), "89abcdef0123456789abcdef0123456789abcdef"
        self.answer(run(21))
        text, error = self.call("ops", "set_reminder", {"note": "Deploy the second one.",
                                                        "ci": {"repo": REPO, "commit": other}}, other_task)
        self.assertFalse(error, text)
        second = hub.q1("SELECT id FROM reminders WHERE task=? AND done=0", (other_task,))["id"]
        real = hub.ci_runs_read

        def read(repo, commit, token, etag=None):
            if commit == COMMIT:
                raise ValueError("broken")
            return real(repo, commit, token, etag)
        self.answer(run(21, status="completed", conclusion="success"))
        with patch.object(hub, "ci_runs_read", side_effect=read):
            hub.ci_pass()
        ci = lambda rid: hub.ci_of(hub.q1("SELECT * FROM reminders WHERE id=?", (rid,)))
        self.assertEqual(ci(first)["runs"][0]["status"], "in_progress")         # as it was
        self.assertEqual((ci(second)["runs"][0]["status"], ci(second)["end"]), ("completed", "completed"))
        line = hub.q1("SELECT what FROM log WHERE what LIKE 'the CI wait of %' ORDER BY id DESC LIMIT 1")["what"]
        self.assertEqual(line, f"the CI wait of {COMMIT[:12]} in {REPO} could not be read: ValueError")

    # ---- the call
    def test_the_call_refuses_a_repository_not_held_a_short_commit_and_one_that_github_does_not_show(self):
        dev_task = self.task_for("dev")
        said, error = self.call("dev", "set_reminder", {"note": "x", "ci": {"repo": REPO, "commit": COMMIT}}, dev_task)
        self.assertTrue(error)
        self.assertIn("You do not hold the repository acme/web", said)
        said, error = self.wait(ci={"repo": REPO, "commit": COMMIT[:12]})
        self.assertTrue(error)
        self.assertIn("40 hex characters", said)
        said, error = self.wait(minutes=5)
        self.assertTrue(error)
        self.assertIn("Give one of minutes", said)
        self.github.answers.append((404, {"message": "Not Found"}, {}))
        said, error = self.wait()
        self.assertTrue(error)
        self.assertIn("The hub cannot read the GitHub Actions runs of acme/web: GitHub answered 404", said)
        self.assertIsNone(hub.q1("SELECT id FROM reminders WHERE task=?", (self.task,)))
        self.assertEqual(self.tokens[0], ({REPO: "read"}, "ops"))
        self.assertTrue(self.github.seen and all(seen["lock_free"] for seen in self.github.seen), self.github.seen)

    def test_runs_that_already_ended_are_said_at_once_with_no_wait(self):
        """With no wait, and the reading is kept as a closed row for the task's result: after one failed run that is
        not run again, each later wait of that commit answers at once, so this row is its only newer reading."""
        other = hub.ins("INSERT INTO reminders(due,note,agent,task,created) VALUES(?,?,?,?,?)",
                        (hub.now() + 3600, "Look again at noon.", "ops", self.task, hub.now()))
        self.answer(run(11, status="completed", conclusion="success"))
        text, error = self.wait()
        self.assertFalse(error, text)
        self.assertIn("All GitHub Actions runs of", text)
        self.assertIn("No wait was set", text)
        r, ci = self.row()
        self.assertEqual((r["done"], r["ci_open"], ci["end"], ci["runs"][0]["id"]), (1, None, "completed", 11))
        self.assertEqual(hub.q1("SELECT done FROM reminders WHERE id=?", (other,))["done"], 0)    # not closed
        self.assertEqual(hub.parked(self.task)["id"], other)        # and the closed row parks nothing
        # a call again, as an agent in a loop makes it, writes the same row again and adds none
        self.answer(run(11, status="completed", conclusion="success"), run(12, status="completed", conclusion="success"))
        self.assertFalse(self.wait()[1])
        again, ci = self.row()
        self.assertEqual((again["id"], len(ci["runs"])), (r["id"], 2))
        self.assertGreaterEqual(again["due"], r["due"])

    # ---- the reading at the start of a result (the hub checks, version 2)
    def deliver(self, task):
        return self.ok("ops", "deliver_result", {"what_was_done": "Shipped it.", "where_output_is": f"{REPO} {COMMIT}",
                                                 "how_checked": "CI is green."}, task)

    def closed_wait(self, task, ci, due=1763560320.0):
        """A CI wait of `task` that ended, as ci_store or the at-once read leaves it: its runs as ci_runs_read keeps
        them (attempt, not GitHub's run_attempt)."""
        ci = dict(ci, runs=[{"id": r["id"], "attempt": r["run_attempt"], "name": r["name"], "status": r["status"],
                             "conclusion": r["conclusion"]} for r in ci.get("runs") or []])
        return hub.ins("INSERT INTO reminders(due,note,agent,task,created,ci,ci_open,done) VALUES(?,?,?,?,?,?,NULL,1)",
                       (due, "x", "ops", task, due, json.dumps(dict({"repo": REPO, "commit": COMMIT}, **ci))))

    def test_a_result_starts_with_the_hubs_reading_of_its_ci_waits_and_one_with_none_reads_as_before(self):
        self.waiting()
        self.answer(run(11, status="completed", conclusion="success"),
                    run(12, name="Deploy", status="completed", conclusion="failure", attempt=2))
        t0 = hub.now()
        hub.ci_pass(t0)
        reads = len(self.github.seen)
        self.deliver(self.task)
        said = self.said_to("manager")
        self.assertEqual(len(self.github.seen), reads)              # a delivery makes no GitHub call
        when = __import__("time").strftime("%Y-%m-%d %H:%M:%S UTC", __import__("time").gmtime(t0))
        self.assertTrue(said.startswith(
            f"[hub] Read by the hub at GitHub for {hub.tref(self.task)}, in its CI waits. {REPO} {COMMIT}, {when}: "
            f"GitHub listed 2 Actions runs: 1 succeeded (run 11 attempt 1); 1 ended without success (run 12 attempt "
            f"2). A run or an attempt after a time above is not in this reading. End of the hub's reading. "
            f"[hub] Result for {hub.tref(self.task)} "), said)
        self.assertNotIn("Deploy", said.split("[hub] Result for")[0])       # no text of GitHub in the reading
        plain = self.task_for("ops")
        self.deliver(plain)
        self.assertTrue(self.said_to("manager").startswith(f"[hub] Result for {hub.tref(plain)} "))

    def test_each_end_has_true_words_and_every_run_is_in_one_group(self):
        """A wait that read nothing never reads as "0 ended without success", a false green; a run of a status that
        the hub does not know is in a group, and the groups sum to the total."""
        line = lambda **ci: hub.ci_reading_line(dict({"repo": REPO, "commit": COMMIT}, **ci), 1763560320.0)
        self.assertEqual(line(end="none"), f"{REPO} {COMMIT}, 2025-11-19 13:52:00 UTC: GitHub listed no Actions run in "
                                           f"15 reads.")
        self.assertIn("the hub could not read its runs: 8 reads in a row failed.", line(end="unread"))
        self.assertIn("the agent no longer held the repository", line(end="lost"))
        self.assertEqual(line(runs=[run(11)]), f"{REPO} {COMMIT}: its wait did not end before the delivery, so the "
                                               f"hub gives no reading of its runs.")
        runs = [{"id": 1, "attempt": 1, "status": None, "conclusion": None},
                {"id": 2, "attempt": 1, "status": "completed", "conclusion": "skipped"},
                {"id": 3, "attempt": 1, "status": "waiting", "conclusion": None},
                {"id": "4", "attempt": 1, "status": "completed", "conclusion": "success"},
                {"id": 5, "attempt": 1, "status": "completed", "conclusion": "action_required"}]
        self.assertEqual(line(end="person", runs=runs).split(": ", 1)[1],
                         "GitHub listed 5 Actions runs: 2 waited for a person (run 3 attempt 1, run 5 attempt 1); 1 "
                         "ended another way (run 2 attempt 1); 1 had not ended (run 1 attempt 1); and 1 that the hub "
                         "left out.")
        self.assertIsNone(line(end="completed", repo="acme/web; rm -rf"))
        self.assertIsNone(line(end="completed", runs=[{"id": "1", "attempt": 1}]))     # no run left: no line at all

    def test_the_newest_reading_by_time_wins_not_the_newest_row(self):
        """A green at-once row of before can have a higher id than a wait of the same commit that ended after it with
        a failed run; by id, the reading would give the old green while the hub holds the newer failure."""
        failed = {"end": "failed", "runs": [run(9, status="completed", conclusion="failure", attempt=2)]}
        self.closed_wait(self.task, failed, due=1763560320.0 + 600)
        self.closed_wait(self.task, {"end": "completed", "at_once": True,
                                     "runs": [run(9, status="completed", conclusion="success")]}, due=1763560320.0)
        said = hub.ci_reading(self.task)
        self.assertIn("1 ended without success (run 9 attempt 2)", said)
        self.assertNotIn("succeeded", said)
        # a wait that started after that end and has not ended is the newest: the hub gives no counts of before
        hub.ins("INSERT INTO reminders(due,note,agent,task,created,ci,ci_open) VALUES(?,?,?,?,?,?,1)",
                (hub.now() + 7200, "x", "ops", self.task, 1763560320.0 + 900,
                 json.dumps({"repo": REPO, "commit": COMMIT, "runs": [run(10)]})))
        said = hub.ci_reading(self.task)
        self.assertIn("its wait did not end before the delivery", said)
        self.assertNotIn("ended without success", said)

    def test_a_fault_of_the_reading_loses_no_result_message(self):
        """The state write commits at once, so a fault after it would lose the result message for good."""
        self.closed_wait(self.task, {"end": "completed", "runs": [run(11, status="completed", conclusion="success")]})
        with patch.object(hub, "ci_reading", side_effect=RuntimeError("broken")), patch.object(hub, "print_fault"):
            self.deliver(self.task)
        self.assertTrue(self.said_to("manager").startswith(f"[hub] Result for {hub.tref(self.task)} "))

    def test_a_parents_reading_carries_its_accepted_parts_at_each_level_and_says_what_it_left_out(self):
        part, refused, deeper, under_refused = (self.task_for("ops") for _ in range(4))
        for tid, parent, accepted in ((part, self.task, 1), (refused, self.task, 0), (deeper, part, 1),
                                      (under_refused, refused, 1)):
            hub.q("UPDATE tasks SET parent=?, state='completed', accepted=? WHERE id=?", (parent, accepted, tid))
        ended = {"end": "completed", "runs": [run(7, status="completed", conclusion="success")]}
        for n, tid in enumerate((part, refused, deeper, under_refused)):
            self.closed_wait(tid, ended, due=1763560320.0 + 60 * n)     # deeper read after part
        said = hub.ci_reading(self.task)
        self.assertTrue(said.startswith(f"[hub] Read by the hub at GitHub for {hub.tref(self.task)}, in its CI waits "
                                        f"and those of its accepted parts. In its part {hub.tref(deeper)}: "), said)
        self.assertIn(f"In its part {hub.tref(part)}: {REPO} {COMMIT}", said)
        self.assertNotIn(hub.tref(refused), said)
        self.assertNotIn(hub.tref(under_refused), said)
        for n in range(7):          # the task's own come first, then the parts' newest, and the cap says what it left
            self.closed_wait(self.task, dict(ended, commit=f"{n:040x}"))
        said = hub.ci_reading(self.task)
        self.assertEqual(said.count(f"{REPO} "), hub.CI_READ_COMMITS)
        self.assertIn(f"In its part {hub.tref(deeper)}: ", said)                 # the newer part stays
        self.assertNotIn(f"In its part {hub.tref(part)}: ", said)
        self.assertIn("And 1 more commit that this reading does not name.", said)

    def test_the_wait_parks_the_task_with_no_time_for_the_apps(self):
        rid = self.waiting()
        r, ci = self.row()
        self.assertEqual(r["ci_open"], 1)
        # its time is for a hub of an older release only: this code does not bring the agent back at it
        self.assertGreater(r["due"], hub.now() + hub.CI_OLD_DUE - 60)
        hub.reminder_sweep(r["due"] + 1)
        self.assertEqual(self.row()[0]["done"], 0)
        self.assertEqual((ci["repo"], ci["commit"], ci["runs"][0]["status"]), (REPO, COMMIT, "in_progress"))
        self.assertEqual(hub.parked(self.task)["id"], rid)
        self.assertEqual(hub.live_reason(hub.q1("SELECT * FROM tasks WHERE id=?", (self.task,)), None),
                         ("reminder", f"R-{rid}"))
        self.assertEqual(hub.park_said(hub.parked(self.task)),
                         "for the GitHub Actions runs of 0123456789ab in acme/web")
        hub.q("UPDATE tasks SET live_path=? WHERE id=?", (f"waiting {hub.park_said(r)}, as ops asked", self.task))
        self.assertNotIn(self.task, hub.parked_until())
        hub.reminder_sweep(hub.now())                   # no time: nothing fires
        self.assertEqual(self.row()[0]["done"], 0)

    # ---- the ends
    def test_all_runs_completed_ends_the_wait_and_the_reminder_brings_the_words(self):
        rid = self.waiting()
        self.answer(run(11, status="completed", conclusion="success"), run(12, name="Lint"))
        hub.ci_pass()
        self.assertIsNone(self.row()[1].get("end"))
        self.answer(run(11, status="completed", conclusion="success"),
                    run(12, name="Lint\x1b[31m", status="completed", conclusion="success"))
        t0 = hub.now()
        hub.ci_pass(t0)
        r, ci = self.row()
        self.assertEqual((r["due"], ci["end"]), (t0, "completed"))
        self.assertIn("All GitHub Actions runs of " + COMMIT + " in acme/web completed.", ci["result"])
        self.assertIn("Lint?[31m: completed, conclusion success (run 12, attempt 1)", ci["result"])
        self.assertIn("These are the GitHub Actions runs only", ci["result"])
        self.assertIsNone(hub.parked(self.task))
        hub.reminder_sweep(t0 + 1)
        self.assertEqual(self.row()[0]["done"], 1)
        said = hub.q("SELECT text FROM events WHERE agent='ops' AND text LIKE ?", (f"%Reminder R-{rid}%",))
        self.assertTrue(any("conclusion success" in e["text"] for e in said), said)

    def test_a_failed_run_ends_it_at_once_and_a_run_that_waits_for_a_person_too(self):
        self.waiting()
        self.answer(run(11, status="completed", conclusion="failure"), run(12))
        hub.ci_pass()
        self.assertEqual(self.row()[1]["end"], "failed")
        self.assertIn("ended without success", self.row()[1]["result"])
        self.task = self.task_for("ops")
        self.waiting()
        self.answer(run(11, status="waiting"), run(12))
        hub.ci_pass()
        self.assertEqual(self.row()[1]["end"], "person")

    def test_a_rerun_during_the_wait_keeps_it_open_until_its_latest_attempt_ends(self):
        self.waiting()
        self.answer(run(11, status="completed", conclusion="success"), run(12, status="in_progress"))
        hub.ci_pass()
        self.answer(run(11, status="queued", attempt=2), run(12, status="completed", conclusion="success"))
        hub.ci_pass()
        self.assertIsNone(self.row()[1].get("end"))
        self.answer(run(11, status="completed", conclusion="success", attempt=2),
                    run(12, status="completed", conclusion="success"))
        hub.ci_pass()
        self.assertEqual(self.row()[1]["end"], "completed")
        self.assertIn("(run 11, attempt 2)", self.row()[1]["result"])

    def test_a_turn_or_a_new_attempt_does_not_end_the_park_of_a_ci_wait(self):
        rid = self.waiting()
        hub.kv_set(f"park_ended:{rid}", hub.now())              # a turn of the session started after the wait was set
        hub.q("UPDATE attempts SET created=? WHERE task=?", (hub.now() + 5, self.task))    # and a new attempt came
        self.assertEqual(hub.parked(self.task)["id"], rid)
        self.assertEqual(hub.live_reason(hub.get_task(self.task), {})[0], "reminder")
        clock = self.call("ops", "set_reminder", {"note": "Look again.", "minutes": 30}, self.task)
        self.assertFalse(clock[1], clock[0])
        timed = self.row()[0]
        self.assertIsNone(timed["ci_open"])
        hub.kv_set(f"park_ended:{timed['id']}", hub.now())      # a reminder of a time still ends its park so
        self.assertIsNone(hub.parked(self.task))

    def test_a_wait_ends_when_its_agent_no_longer_holds_the_repository(self):
        rid = self.waiting()
        reads = len(self.github.seen)
        team = {name: dict(a) for name, a in hub.agents().items()}
        team["ops"]["repos"] = {}
        with patch.object(hub, "agents", return_value=team):
            hub.ci_pass()
        r, ci = self.row()
        self.assertEqual((r["id"], ci["end"], r["ci_open"]), (rid, "lost", None))
        self.assertIn("You no longer hold acme/web", ci["result"])
        self.assertEqual(len(self.github.seen), reads)          # and GitHub was not asked for it

    # ---- the counts
    def test_fifteen_reads_in_a_row_with_no_run_end_it_and_a_run_resets_the_count(self):
        self.github.answers.append((200, {"total_count": 0, "workflow_runs": []}, {}))
        self.assertFalse(self.wait()[1])
        for _ in range(hub.CI_NO_RUN_READS - 2):
            self.answer()
            hub.ci_pass()
        self.assertEqual(self.row()[1]["empty"], 14)
        self.assertEqual(self.row()[0]["ci_open"], 1)
        self.answer()
        hub.ci_pass()
        self.assertEqual(self.row()[1]["end"], "none")
        self.assertIn("No GitHub Actions run of " + COMMIT + " in acme/web appeared in 15 reads",
                      self.row()[1]["result"])
        self.task = self.task_for("ops")
        self.waiting()
        self.answer()
        hub.ci_pass()
        self.assertEqual(self.row()[1]["empty"], 1)

    def test_eight_failed_reads_in_a_row_end_it_and_a_rate_limit_only_pauses(self):
        self.waiting()
        for _ in range(hub.CI_FAILED_READS - 1):
            self.github.answers.append((502, {}, {}))
            hub.ci_pass()
        self.github.answers.append((403, {"message": "API rate limit exceeded"}, {"X-RateLimit-Remaining": "0"}))
        hub.ci_pass()
        self.github.answers.append((429, {}, {"Retry-After": "60"}))
        hub.ci_pass()
        _, ci = self.row()
        self.assertEqual((ci["failed"], ci.get("end")), (7, None))
        self.github.answers.append((502, {}, {}))
        hub.ci_pass()
        self.assertEqual(self.row()[1]["end"], "unread")
        self.assertIn("8 times in a row: GitHub answered 502", self.row()[1]["result"])

    def test_one_read_each_pass_for_all_waits_of_a_commit_with_if_none_match(self):
        self.github.answers.append((200, {"workflow_runs": [run(11)]}, {"ETag": 'W/"a1"'}))
        self.assertFalse(self.wait()[1])
        other = self.task_for("ops")
        self.github.answers.append((200, {"workflow_runs": [run(11)]}, {"ETag": 'W/"a1"'}))
        self.assertFalse(self.call("ops", "set_reminder", {"note": "Also this.", "ci": {"repo": REPO, "commit": COMMIT}},
                                   other)[1])
        seen = len(self.github.seen)
        self.github.answers.append((304, {}, {}))
        hub.ci_pass()
        self.assertEqual(len(self.github.seen), seen + 1)                  # one read for both waits
        self.assertEqual(self.github.seen[-1]["etag"], 'W/"a1"')
        self.assertIn(f"head_sha={COMMIT}", self.github.seen[-1]["path"])
        self.assertEqual(self.github.seen[-1]["auth"], "Bearer ghs_standin")
        self.assertTrue(all(seen["lock_free"] for seen in self.github.seen), self.github.seen)
        rows = hub.q("SELECT ci FROM reminders WHERE done=0 AND ci IS NOT NULL")
        self.assertEqual([json.loads(r["ci"])["runs"][0]["status"] for r in rows], ["in_progress", "in_progress"])

    # ---- what lasts and what ends it by itself
    def test_a_restart_of_the_hub_keeps_the_wait_and_its_counts(self):
        self.waiting()
        self.github.answers.append((502, {}, {}))
        hub.ci_pass()
        hub.CI_TOKENS.clear()                   # what a restart forgets; the row is in the database
        self.assertEqual(hub.build_schema(), [])
        self.assertEqual(self.row()[1]["failed"], 1)
        self.answer(run(11, status="completed", conclusion="success"))
        hub.ci_pass()
        self.assertEqual(self.row()[1]["end"], "completed")

    def test_a_wait_whose_task_ended_ends_with_it(self):
        self.waiting()
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (self.task,))
        seen = len(self.github.seen)
        hub.ci_pass()
        self.assertEqual(self.row()[0]["done"], 1)
        self.assertEqual(len(self.github.seen), seen)

    def test_the_watcher_survives_every_exception(self):
        calls = []

        def once():
            calls.append(1)
            if len(calls) == 1:
                raise ValueError("a fault")
            raise Stop()
        with patch.object(hub, "ci_pass", side_effect=once), patch.object(hub, "CI_EVERY", 0):
            with self.assertRaises(Stop):
                hub.ci_watcher()
        self.assertEqual(len(calls), 2)
        self.waiting()
        with patch.object(hub, "ci_runs_read", side_effect=RuntimeError("broken")):
            hub.ci_pass()                       # one commit's fault: logged, and no exception out
        line = hub.q1("SELECT what FROM log WHERE what LIKE 'the CI wait of%' ORDER BY id DESC LIMIT 1")
        self.assertEqual(line["what"], "the CI wait of 0123456789ab in acme/web could not be read: RuntimeError")


if __name__ == "__main__":
    unittest.main()

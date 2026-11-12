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
        threading.Thread(target=self.github.serve_forever, daemon=True).start()
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
        self.answer(run(11, status="completed", conclusion="success"))
        text, error = self.wait()
        self.assertFalse(error, text)
        self.assertIn("All GitHub Actions runs of", text)
        self.assertIn("No wait was set", text)
        self.assertIsNone(hub.q1("SELECT id FROM reminders WHERE task=?", (self.task,)))

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

"""A screen session that failed. The helper starts its attempt one time, the record reader sends its last records
also when its window was gone before any look, and the hub pauses the task and tells the requester.

A local hub, a real helper object and the real record reader, with stand-ins for tmux and for the runner. No AI
calls, no remote calls, no real session."""
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import fleet
from leftovers import scratch_home
import hub
import threads
from test_ui_api import own_attachments

SESSION = "0b7d5a8e-3c1f-4e2a-9d6b-1f2e3d4c5b6a"
REASON = "Codex model/list has 0 default models, not one"
# The one record that the runner writes for a stop of its own, before it ends (the agreed contract).
RUNNER_STOP = {"method": "turn/completed", "params": {"turn": {"id": "fleet-stop", "status": "failed",
                                                               "error": {"message": REASON}}}}
DANA = {"role": "worker", "runtime": "claude", "machine": "dana-mac", "can": ["shell", "browser", "screen"],
       "screen_command": "/synthetic/codex"}


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def error(seq, code="bad_request", message="The model `synthetic-old` is not supported.", **more):
    return dict({"seq": seq, "ts": time.time(), "type": "error", "code": code, "message": message, "retryable": False}, **more)


def result(seq, stop="error"):
    return {"seq": seq, "ts": time.time(), "type": "result", "stop_reason": stop}


class ScreenFailure(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fleet-screen-failure-test-")
        own_attachments(self, self.tmp.name + "/attachments")     # hub.tick() sweeps it
        hub.DB = sqlite3.connect(self.tmp.name + "/test.db", check_same_thread=False)
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        hub.migrate()
        # This team pins no agent to an address on purpose: these checks are about what a session's records do to a
        # task, they drive two agents' helper routes from this one process, and both would need an address of their
        # own. A hub that tells no agent apart by address takes the name as given (hub.address_checked), and the one
        # desktop at a time of owner API 1.12 is a machine rule as well, so each check keeps its own screen tasks.
        hub.TEAM = {"addresses": {"owner": "127.0.0.1"},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                               "dana": DANA,
                               "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio",
                                          "can": ["shell", "browser"]}}}
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90,
                       ask_wait=1, ask_max=1, hook_wait=2, job_wait=1, tick=5)
        hub.kv_set("db_id", "gen1")
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), hub.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        hub.DB.close()
        self.tmp.cleanup()

    # ---- the hub
    def call(self, method, path, body=None, client="deterministic-test"):
        headers = {"Content-Type": "application/json"}
        if client:
            headers["X-Fleet-Client"] = client
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers=headers, method=method)
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            with response:
                return response.code, json.load(response)

    def task(self, owner="dana", needs="screen", state="working"):
        text = hub.t_create_task("manager", {"owner": owner, "title": "Read the page on the screen",
                                             "done_when": "the answer is delivered", "needs": needs})
        tid = int(text.split()[1][2:].rstrip("."))
        if state != "submitted":
            hub.q("UPDATE tasks SET state=?, started=? WHERE id=?", (state, hub.now() - 100, tid))
        return tid

    def records(self, tid, events, attempt=1, session=SESSION, agent="dana"):
        return self.call("POST", f"/helper/events/{agent}", dict(generation="gen1", task=f"T-{tid}", attempt=attempt,
                                                                 session=session, events=events), client=None)

    def holds(self, tid):
        return [dict(r) for r in hub.q("SELECT * FROM holds WHERE task=? ORDER BY id", (tid,))]

    def said(self, agent, kind="say"):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent=? AND kind=? ORDER BY id", (agent, kind))]

    def delivered(self, agent, alive=""):
        return self.call("GET", f"/events/{agent}?delivery=1&after=0&wait=0&alive={alive}", client=None)[1]["events"]

    def stored(self, tid):
        return [(r["type"], json.loads(r["data"])) for r in
                hub.q("SELECT type, data FROM thread_events WHERE task=? ORDER BY session, seq", (tid,))]

    # ---- the helper, with stand-ins for tmux and for the runner
    def helper(self, runner):
        """A helper for dana. `runner(session)` is the screen runner's whole life at its start; after it the window is
        `self.open` (a set of window names). The helper's hub is this test's hub, and its reader reads in the
        test's folder."""
        self.open, self.starts, self.said_by_helper = set(), [], []
        helper = fleet.Helper("dana", DANA)
        helper.tailer.home = self.tmp.name
        helper.sync_checkout = lambda: None             # no pull of the checkout in a test
        helper.say = self.said_by_helper.append

        def start_window(session, name, command):
            self.starts.append((name, command))
            found = re.search(r"FLEET_SESSION=([0-9a-f-]{36})", command)        # only a screen runner has it
            runner(found.group(1) if found else "")

        def tmux(*args, check=False, **kw):
            gone = not self.open            # no task window: tmux refuses an option for it, and lists none
            if args[0] == "list-windows":
                return subprocess.CompletedProcess(args, 0, "".join(self.listed.get(w, w) + "\n" for w in sorted(self.open)), "")
            if gone and check:
                raise subprocess.CalledProcessError(1, args, "", "can't find window")
            return subprocess.CompletedProcess(args, 1 if gone else 0, "", "")
        self.listed = {}
        for name, stand_in in (("start_window", start_window), ("tmux", tmux), ("windows", lambda session: ["home", *self.open]),
                               ("session_credential", lambda *a, **k: None)):
            p = patch.object(fleet, name, stand_in)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(fleet, "HUB", self.base)
        p.start()
        self.addCleanup(p.stop)
        return helper

    def record_file(self, session, rows):
        os.makedirs(os.path.join(self.tmp.name, ".fleet"), exist_ok=True)
        with open(os.path.join(self.tmp.name, ".fleet", f"screen-{session}.jsonl"), "a", encoding="utf-8") as f:
            for row in rows:
                f.write(json.dumps(dict(row, timestamp=time.time())) + "\n")

    # ---- the whole path
    def test_a_runner_that_ends_before_any_look_gives_one_error_one_hold_and_no_second_start(self):
        tid = self.task(state="submitted")              # as T-105: no Fleet tool call yet
        name = f"T-{tid}"
        # The runner writes its one record and ends at once: its window is gone before the helper can give it an
        # option, and before the reader looks at the windows.
        helper = self.helper(lambda session: self.record_file(session, [RUNNER_STOP]))
        event = next(e for e in self.delivered("dana") if e["kind"] == "task")
        with self.assertRaises(subprocess.CalledProcessError):      # the helper's loop logs it: the event stays pending
            helper.handle(event)
        self.assertEqual(len(self.starts), 1)
        self.assertEqual(self.stored(tid), [])
        # The reader's next look finds no window, and sends the records of the session that the helper started.
        helper.tailer.scan()
        self.assertEqual(self.stored(tid), [("error", {"code": "error", "message": REASON, "retryable": False, "resets_at": None}),
                                            ("result", {"stop_reason": "error"})])
        self.assertEqual(helper.tailer.feeds, {})                   # read to its end and sent: no feed stays
        # One hold, the existing pause in the requester's name, with its control event, and one message.
        (hold,) = self.holds(tid)
        self.assertEqual((hold["kind"], hold["by"], hold["state"], hold["attempt"]), ("pause", "manager", "requested", 1))
        (notice,) = self.said("manager")
        self.assertIn(f"The hub paused {name} (Read the page on the screen, owner dana)", notice)
        self.assertIn(REASON, notice)
        self.assertIn("starts no new session and gets no messages", notice)
        self.assertEqual([json.loads(r["extra"])["action"] for r in
                          hub.q("SELECT extra FROM events WHERE agent='dana' AND kind='control'")], ["pause"])
        # Nothing starts or types into that attempt again: the hub gives no task event, and a task event that still
        # comes (the poll that was on its way) starts nothing. The reader sends nothing two times.
        self.assertEqual([e["kind"] for e in self.delivered("dana")], ["control"])
        for _ in range(3):
            helper.handle(event)
            helper.tailer.scan()
        self.assertEqual(len(self.starts), 1)
        self.assertEqual(self.said_by_helper, [f"{name}: the screen runner of attempt 1 ended; the helper does not "
                                               f"start the same attempt again"])
        self.assertEqual(len(self.stored(tid)), 2)
        self.assertEqual(len(self.holds(tid)), 1)
        # The helper's answer to the pause is the existing proof (control() sends it): the hold is confirmed.
        self.assertEqual(self.call("POST", "/helper/control/dana", {"hold": hold["id"], "confirmed": True, "ran": False,
                                   "detail": "no session was running", "flushed": [], "ended": 0}, client=None)[1]["state"], "stopped")
        # The timers start no attempt and send no other message, also after a long time.
        hub.q("UPDATE tasks SET created=created-3600 WHERE id=?", (tid,))
        hub.q("UPDATE agents SET last_seen=?, alive='', alive_ts=? WHERE name='dana'", (hub.now(), hub.now()))
        hub.tick()
        self.assertEqual(hub.q1("SELECT attempt, live_path FROM tasks WHERE id=?", (tid,))["attempt"], 1)
        self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"], "paused by the manager")
        self.assertEqual(len(self.said("manager")), 1)
        # The owner's Resume works as on every hold: a new attempt, which the helper starts one time.
        code, body = self.call("POST", f"/ui/tasks/{tid}/control", {"request_id": str(uuid.uuid4()), "db": "gen1", "action": "resume"})
        self.assertEqual((code, body["resumed_with"]), (200, "new session"))
        again = next(e for e in self.delivered("dana") if e["kind"] == "task")
        self.assertEqual(again["extra"]["attempt"], 2)
        with self.assertRaises(subprocess.CalledProcessError):      # this stand-in runner ends at once too
            helper.handle(again)
        self.assertEqual(len(self.starts), 2)

    # ---- the hub: what is a failed session, and what is not
    def test_a_failed_turn_of_the_runtime_pauses_a_working_screen_task_one_time(self):
        tid = self.task()
        self.assertEqual(self.records(tid, [error(1)])[0], 200)          # the error comes first, in a batch of its own
        self.assertEqual(self.holds(tid), [])                            # an error alone is no end of a turn
        self.assertEqual(self.records(tid, [result(2)])[0], 200)
        (hold,) = self.holds(tid)
        self.assertEqual((hold["kind"], hold["by"], hold["state"]), ("pause", "manager", "requested"))
        self.assertIn("The error: The model `synthetic-old` is not supported.", self.said("manager")[0])
        # The same batch again, and a second failed turn of a runner that still ran: one hold and one message.
        self.records(tid, [result(2)])
        self.records(tid, [error(3), result(4)])
        self.assertEqual(len(self.holds(tid)), 1)
        self.assertEqual(len(self.said("manager")), 1)
        self.assertNotIn("task", [e["kind"] for e in self.delivered("dana", alive="")])

    def test_a_report_retry_recovers_a_failure_stored_before_the_hub_stopped(self):
        tid = self.task(state="submitted")
        # Model a hub stop between storing the result and making the pause: the caller got no receipt.
        with patch.object(hub, "screen_failed"):
            self.assertEqual(self.records(tid, [error(1), result(2)])[0], 200)
        self.assertEqual(self.holds(tid), [])
        # On reconnect the reader first asks for the last sequence with an empty batch.
        self.assertEqual(self.records(tid, [])[1]["last_seq"], 2)
        self.assertEqual(len(self.holds(tid)), 1)
        self.assertEqual(len(self.said("manager")), 1)
        self.records(tid, [error(1), result(2)])
        self.assertEqual(len(self.holds(tid)), 1)
        self.assertEqual(len(self.said("manager")), 1)

    def test_a_usage_limit_stays_the_limit_wait_and_is_no_session_failure(self):
        tid = self.task()
        limit = error(1, code="usage_limit", message="You have hit your usage limit.", retryable=True, resets_at=time.time() + 600)
        self.assertEqual(self.records(tid, [limit, result(2)])[0], 200)
        self.assertEqual(self.holds(tid), [])
        self.assertIsNotNone(hub.active_limit("dana"))
        self.assertFalse(any("paused" in text for text in self.said("manager")))
        # Also when the limit's error came in an earlier batch, and when its reset time is over (no wait starts).
        other = self.task()
        self.records(other, [dict(limit, resets_at=time.time() - 5)], session=str(uuid.uuid4()))
        hub.q("UPDATE agent_limits SET ended=? WHERE ended IS NULL", (hub.now(),))
        session = str(uuid.uuid4())
        self.records(other, [dict(limit, resets_at=None)], session=session)
        hub.q("UPDATE agent_limits SET ended=? WHERE ended IS NULL", (hub.now(),))
        self.records(other, [result(2)], session=session)
        self.assertEqual(self.holds(other), [])

    def test_a_tool_call_that_failed_and_a_turn_that_ended_in_another_way_pause_nothing(self):
        tid = self.task()
        call = {"seq": 1, "ts": time.time(), "type": "tool_call", "tool_call_id": "c1", "status": "pending",
                "title": "cua_repl", "kind": "other", "server": "cua"}
        failed = {"seq": 2, "ts": time.time(), "type": "tool_call_update", "tool_call_id": "c1", "status": "failed", "output": "refused"}
        self.assertEqual(self.records(tid, [call, failed, result(3, "end_turn"), error(4), result(5, "cancelled")])[1]["stored"], 5)
        self.assertEqual(self.holds(tid), [])
        self.assertEqual(self.said("manager"), [])
        # A failed result with no error record of its turn (the error before it belongs to the turn that was stopped).
        self.records(tid, [result(6)])
        (hold,) = self.holds(tid)
        self.assertIn("The error: The session gave no error text.", self.said("manager")[0])

    def test_only_the_current_attempt_of_an_open_screen_task_is_paused(self):
        browser = self.task(owner="studio", needs="browser")
        self.records(browser, [error(1), result(2)], agent="studio")
        self.assertEqual(self.holds(browser), [])                        # a terminal session stays open after a failed turn
        old = self.task()
        hub.new_attempt(hub.q1("SELECT * FROM tasks WHERE id=?", (old,)), "restart")
        self.assertEqual(self.records(old, [error(1), result(2)], attempt=1)[0], 200)
        self.assertEqual(self.holds(old), [])                            # the records of an earlier attempt
        done = self.task()
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (done,))
        self.records(done, [error(1), result(2)])
        self.assertEqual(self.holds(done), [])
        held = self.task()
        self.assertEqual(self.call("POST", f"/ui/tasks/{held}/control", {"request_id": str(uuid.uuid4()), "db": "gen1",
                                                                         "action": "stop", "note": ""})[0], 200)
        told = len(self.said("manager"))
        self.records(held, [error(1), result(2)])
        (hold,) = self.holds(held)
        self.assertEqual((hold["kind"], hold["by"]), ("stop", "owner"))  # the owner's hold stays as it is
        self.assertEqual(len(self.said("manager")), told)

    # ---- the helper: one start for each screen attempt, and all other windows as before
    def test_the_helper_starts_a_screen_attempt_one_time_and_each_new_attempt_one_time(self):
        helper = self.helper(lambda session: self.open.add("T-7"))      # the runner runs: its window is there
        event = {"id": 1, "kind": "task", "task": "T-7", "text": "Do T-7.",
                 "extra": {"needs": "screen", "attempt": 1, "generation": "gen1"}}
        helper.handle(event)
        self.assertEqual(len(self.starts), 1)
        self.open.clear()                                               # the runner ended: its window closed
        for _ in range(3):
            helper.handle(event)                                        # the unread task event comes at each poll
        self.assertEqual(len(self.starts), 1)
        self.assertEqual(len(self.said_by_helper), 2)                   # "session started", and one line for the end
        with helper.tailer.lock:                                        # the reader has the session from the start
            self.assertEqual([(f.name, f.attempt, f.translator.runtime) for f in helper.tailer.feeds.values()], [("T-7", 1, "codex_app")])
        helper.handle(dict(event, extra=dict(event["extra"], attempt=2)))    # the hub's new attempt, or a Resume
        self.assertEqual(len(self.starts), 2)
        self.open.clear()
        helper.handle(dict(event, extra=dict(event["extra"], attempt=2)))
        self.assertEqual(len(self.starts), 2)
        fresh = fleet.Helper("dana", DANA)                                # a new helper process, after a restart
        fresh.sync_checkout, fresh.say = lambda: None, self.said_by_helper.append
        fresh.handle(dict(event, extra=dict(event["extra"], attempt=2)))
        self.assertEqual(len(self.starts), 3)

    def test_a_window_that_is_no_screen_runner_starts_again_as_before(self):
        helper = self.helper(lambda session: None)
        conf = dict(DANA, start="claude --permission-mode dontAsk {chrome} {settings} {prompt}")
        helper.conf = conf
        with patch.object(fleet, "session_command", lambda *a, **k: "claude"):
            for needs in ("browser", "none"):
                event = {"id": 2, "kind": "task", "task": "T-8", "text": "Do T-8.",
                         "extra": {"needs": needs, "attempt": 1, "generation": "gen1"}}
                before = len(self.starts)
                for _ in range(2):
                    with self.assertRaises(subprocess.CalledProcessError):      # the stand-in window is gone at once
                        helper.handle(event)
                self.assertEqual(len(self.starts), before + 2)
        self.assertEqual(getattr(helper, "screen_attempts", {}), {})
        self.assertEqual(helper.tailer.feeds, {})

    # ---- the reader: one feed for each session
    def test_the_reader_keeps_one_feed_for_a_session_that_is_registered_and_seen(self):
        posted, live = [], []
        tailer = threads.Tailer("claude", lambda: list(live), lambda batch: posted.append(batch) or (200, {"last_seq": 0}),
                                home=self.tmp.name, screen_requested={"model": None, "effort": None})
        window = ("T-9", "gen1", 1, SESSION, "codex_app")
        live.append(window)
        tailer.scan()                                   # the reader saw the window first
        seen = tailer.feeds[("T-9", SESSION)]
        tailer.register(window[:4], "codex_app")
        tailer.register(window[:4], "codex_app")
        self.assertEqual(list(tailer.feeds.values()), [seen])           # the same feed, and only one
        self.record_file(SESSION, [RUNNER_STOP])
        live.clear()
        tailer.scan()
        self.assertEqual([[e["type"] for e in b["events"]] for b in posted if b["events"]], [["error", "result"]])
        self.assertEqual(tailer.feeds, {})


if __name__ == "__main__":
    unittest.main()

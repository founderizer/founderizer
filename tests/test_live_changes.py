"""Immediate results (owner feature live_changes), hub side: the change signal that the apps wait on, and the one
answer for "signed in" that every screen and every hub check reads. The owner, 25 October 2026, after his manager's
sign-in sent its setup back to the first page for five minutes: "it needs to be immediate". A temporary database and
repository and stand-in helper reports through the real routes: no AI call, no real runtime, no real session."""
import json
import threading
import time
import unittest
from unittest.mock import patch

import hub
from test_manager_switch import FEATURES, ManagerSwitch
from test_runtime_switch import git


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(LiveChanges(name) for name in LiveChanges.__dict__ if name.startswith("test_"))


class LiveChanges(ManagerSwitch):
    def status(self, claude=True, codex=True, age=None, features=FEATURES + ["status_now"]):
        """The manager's helper reports, with the sign-in of each runtime as given and the age of its reading."""
        body = {"revision": git("rev-parse", "HEAD", cwd=self.kit),
                "runtime": {"name": "claude", "version": "1", "signed_in": claude},
                "runtimes": {"codex": {"version": "codex-cli 0.160.0" if codex is not None else None,
                                       "signed_in": codex},
                             "claude": {"version": "2.1.296 (Claude Code)", "signed_in": claude}},
                "update": {"state": None, "detail": None}, "features": features,
                "settings": hub.agent_settings("manager"), "other_runtime_windows": [], "owner_chat_bound": None,
                "manager_bound": True}
        if age is not None:
            body["reading_age"] = age
        code, _ = self.request("/helper/status/manager", body)
        self.assertEqual(code, 200)

    def wait(self, since, wait=0):
        return self.request(f"/ui/wait?db=test-generation&since={since}&wait={wait}")

    def poll(self, alive="manager"):
        return self.request(f"/events/manager?delivery=1&after=0&wait=0&alive={alive}")

    # ---- the change signal
    def test_check_ins_reports_ticks_reads_and_log_lines_move_nothing_the_apps_wait_on(self):
        self.status()
        self.poll()
        hub.tick()
        before = hub.CHANGE["state"]
        for _ in range(3):
            self.poll()                         # a helper's poll with the same windows
            self.status()                       # a report whose only change is its times
            hub.tick()
            hub.log("hub", "a line of the hub's own log")
            self.request("/ui/state")
            self.request("/ui/machines?db=test-generation")
            self.request("/ui/health?db=test-generation")
        self.assertEqual(hub.CHANGE["state"], before)

    def test_a_change_the_owner_sees_wakes_a_waiter_at_once(self):
        token = self.request("/ui/state")[1]["token"]
        self.assertEqual(self.wait(token)[1]["token"], token)           # nothing changed: the same token
        got = {}
        waiter = threading.Thread(target=lambda: got.update(answer=self.wait(token, 5)))
        start = time.monotonic()
        waiter.start()
        time.sleep(0.3)
        self.say("A message that the manager has not read yet.")       # a `with DB:` write: counted too
        waiter.join(5)
        self.assertLess(time.monotonic() - start, 3)
        self.assertNotEqual(got["answer"][1]["token"], token)

    def test_another_boot_or_an_unknown_token_answers_at_once_and_an_old_generation_is_refused(self):
        start = time.monotonic()
        self.assertEqual(self.wait("other.0.0", 5)[0], 200)
        self.assertEqual(self.wait("", 5)[0], 200)
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(self.request("/ui/wait?db=old-generation&since=x&wait=1")[0], 409)

    def test_the_tick_counts_an_agent_going_offline(self):
        with patch.object(hub, "STARTED", hub.now() - 86400):     # silence counts from the hub's start at the earliest
            hub.touch("vps")
            hub.tick()
            before = hub.CHANGE["state"]
            with hub.area("quiet"):                 # time passes: no write says it
                hub.q("UPDATE agents SET last_seen=? WHERE name='vps'", (hub.now() - 1000,))
            hub.tick()
        self.assertGreater(hub.CHANGE["state"], before)

    def test_an_open_tasks_liveness_and_a_rewritten_key_change_nothing_twice(self):
        hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('T','vps','manager','working',?)",
                (hub.now(),))
        hub.tick()
        before = hub.CHANGE["state"]
        hub.tick()
        hub.tick()
        hub.kv_set("releases_checked", hub.kv_get("releases_checked") or "1")
        hub.kv_set("releases_checked", hub.kv_get("releases_checked"))
        self.assertEqual(hub.CHANGE["state"], before + (0 if hub.kv_get("releases_checked") != "1" else 1))

    def test_health_says_how_often_the_signal_moves(self):
        changes = self.request("/ui/health?db=test-generation")[1]["changes"]
        self.assertEqual(set(changes), {"state_per_minute", "activity_per_minute", "waiting"})

    def test_a_window_list_that_changes_counts_and_the_banner_follows_it(self):
        self.status()
        self.poll("manager")
        before = hub.CHANGE["state"]
        self.poll("")                           # the manager's session went
        self.assertGreater(hub.CHANGE["state"], before)
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "down")           # at once, not at the next tick

    # ---- the wait for an answer ends with the manager's turn
    def turn(self, **marks):
        self.assertEqual(self.request("/helper/turn/manager", marks)[0], 200)

    def turn_ended_after(self, name="manager"):
        """What the Mac's read and the phone's read say of this agent: the same value."""
        mac = next(a for a in self.request("/ui/state")[1]["agents"] if a["name"] == name)["turn_ended_after"]
        phone = next(a for a in self.request("/ui/mobile")[1]["agents"] if a["name"] == name)["turn_ended_after"]
        self.assertEqual(mac, phone)
        return mac

    def sent(self, text):
        return hub.q1("SELECT created FROM ui_requests WHERE recipient='manager' AND text=?", (text,))["created"]

    def test_the_end_of_the_turn_that_read_the_owners_message_ends_the_wait_and_wakes_the_apps(self):
        """10 November 2026: a message told the manager to give no answer. It did the work in a turn of 20 seconds and
        wrote none, and the chat said "Thinking" for more than an hour: the apps knew only that the owner's newest
        message had no reply. The manager's helper already told the hub each turn end (plan C1). Now the hub says
        which message the last ended turn had read, and that turn end wakes the apps."""
        self.assertIsNone(self.turn_ended_after())
        self.turn(started=hub.now() - 20, ended=hub.now() - 10)         # a turn before any message
        self.assertIsNone(self.turn_ended_after())
        self.say("The release runs on Wednesday. No answer is necessary.")
        first = self.sent("The release runs on Wednesday. No answer is necessary.")
        before = hub.CHANGE["state"]
        self.turn(started=hub.now())                                    # its turn starts: nothing is read yet
        self.assertEqual((hub.CHANGE["state"], self.turn_ended_after()), (before, None))
        hub.t_read_messages("manager", {})
        self.assertIsNone(self.turn_ended_after())                      # read, and its turn still runs: it works
        token = self.request("/ui/state")[1]["token"]
        got = {}
        waiter = threading.Thread(target=lambda: got.update(answer=self.wait(token, 5)))
        start = time.monotonic()
        waiter.start()
        time.sleep(0.3)
        self.turn(ended=hub.now())                                      # the turn that read it ends, with no reply
        waiter.join(5)
        self.assertLess(time.monotonic() - start, 3)                    # the apps read at once, not at the next change
        self.assertNotEqual(got["answer"][1]["token"], token)
        self.assertEqual(self.turn_ended_after(), first)
        self.assertIsNone(self.turn_ended_after("vps"))                 # an owner chat reports no turns
        # A later turn that read no message of the owner's moves nothing that a screen shows.
        before = hub.CHANGE["state"]
        self.turn(started=hub.now(), ended=hub.now())
        self.assertEqual((hub.CHANGE["state"], self.turn_ended_after()), (before, first))
        # The next message waits again until the turn that reads it has ended.
        self.say("And the watch runs to 19:00.")
        second = self.sent("And the watch runs to 19:00.")
        self.assertGreater(second, first)
        self.assertEqual(self.turn_ended_after(), first)                # unread
        hub.t_read_messages("manager", {})
        self.assertEqual(self.turn_ended_after(), first)                # read, in a turn that runs
        before = hub.CHANGE["state"]
        self.turn(ended=hub.now())
        self.assertEqual((hub.CHANGE["state"], self.turn_ended_after()), (before + 1, second))

    def test_an_old_turn_end_and_an_answer_to_a_request_end_no_wait(self):
        """A helper that reads its transcript again sends old marks, and the answer to a Needs-you item is no chat
        message: its card shows it, and neither app waits under it."""
        self.say("What is the status?")
        hub.t_read_messages("manager", {})
        read = hub.q1("SELECT e.read_at FROM ui_requests u JOIN events e ON e.id=u.event_id")["read_at"]
        self.turn(ended=read - 5)                                       # a turn that ended before the read
        self.assertIsNone(self.turn_ended_after())
        self.turn(ended=hub.now())
        asked = self.sent("What is the status?")
        self.assertEqual(self.turn_ended_after(), asked)
        self.assertEqual(self.request(f"/ui/needs/{self.need()}", self.command(answer="The second one."))[0], 200)
        self.assertEqual(hub.q1("SELECT kind FROM ui_requests WHERE text='The second one.'")["kind"], "answer")
        hub.t_read_messages("manager", {})
        before = hub.CHANGE["state"]
        self.turn(ended=hub.now())
        self.assertEqual((hub.CHANGE["state"], self.turn_ended_after()), (before, asked))

    def test_a_turn_that_a_usage_limit_cut_ends_no_wait_while_the_limit_holds(self):
        """A turn that stops at a usage limit ends as every turn does (threads: a result with the stop reason
        "error"), and its helper tells the hub the limit before that end. The message that it read is not done with:
        the apps say "Usage limit" under it, as before, and not nothing. The end counts when the limit is over."""
        self.say("What is the status?")
        asked = self.sent("What is the status?")
        hub.t_read_messages("manager", {})
        self.assertEqual(self.request("/helper/limit/manager", {"resets_at": hub.now() + 3600, "runtime": "claude"})[0], 200)
        before = hub.CHANGE["state"]
        self.turn(ended=hub.now())                                      # the turn that the limit cut
        self.assertEqual((hub.CHANGE["state"], self.turn_ended_after()), (before, None))
        state = self.request("/ui/state")[1]
        self.assertIsNotNone(next(a for a in state["agents"] if a["name"] == "manager")["limit"])
        hub.q("UPDATE agent_limits SET until=? WHERE ended IS NULL", (hub.now() - 1,))
        hub.end_limits(hub.now())                                       # the reset: a change that the apps read
        self.assertGreater(hub.CHANGE["state"], before)
        self.assertEqual(self.turn_ended_after(), asked)

    # ---- one answer for "signed in"
    def test_a_finished_sign_in_is_signed_in_until_a_later_reading_says_otherwise(self):
        self.status(claude=False)
        self.assertIs(hub.signed_in_now("manager", "claude"), False)
        hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('manager','claude','done',?,?)",
                (hub.now(), hub.now()))
        self.assertIs(hub.signed_in_now("manager", "claude"), True)
        row = next(m for m in self.request("/ui/machines?db=test-generation")[1]["machines"] if m["agent"] == "manager")
        self.assertEqual((row["runtime"]["signed_in"], row["runtimes"]["claude"]["signed_in"]), (True, True))
        stored = json.loads(hub.q1("SELECT data FROM machine_status WHERE agent='manager'")["data"])
        self.assertIs(stored["runtimes"]["claude"]["signed_in"], False)        # the machine's own reading stays
        agent = next(a for a in self.request("/ui/state")[1]["agents"] if a["name"] == "manager")
        self.assertIs(agent["signed_in"], True)
        time.sleep(0.01)
        self.status(claude=False)               # a reading taken after it says signed out
        self.assertIs(hub.signed_in_now("manager", "claude"), False)

    def test_a_reading_taken_before_a_sign_in_loses_to_it_however_late_it_arrives(self):
        self.status(claude=False)
        hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('manager','claude','done',?,?)",
                (hub.now(), hub.now()))
        time.sleep(0.01)
        self.status(claude=False, age=30)       # read 30 s ago, before the sign-in, and posted now
        self.assertIs(hub.signed_in_now("manager", "claude"), True)
        self.assertEqual((hub.reading_age_of(-5), hub.reading_age_of(500), hub.reading_age_of("x"),
                          hub.reading_age_of(True), hub.reading_age_of(float("nan"))), (0.0, 120.0, 0.0, 0.0, 0.0))

    def test_nothing_older_than_machine_stale_counts(self):
        self.status(claude=False)
        old = hub.now() - hub.MACHINE_STALE - 10
        hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('manager','claude','done',?,?)",
                (old, old))
        with hub.area("quiet"):
            hub.q("UPDATE machine_status SET reported=? WHERE agent='manager'", (old - 5,))
        self.assertIsNone(hub.signed_in_now("manager", "claude"))

    def test_a_preparation_that_ended_done_is_installed_and_signed_in_for_a_switch(self):
        self.status(codex=None)                 # the manager's machine has no Codex yet
        self.assertIn("runtime_not_installed", hub.runtime_switch("manager")["missing"])
        hub.ins("INSERT INTO server_jobs(server,kind,agent,runtime,state,step,created,updated) "
                "VALUES('hub','prepare','manager','codex','done','sign_in',?,?)", (hub.now(), hub.now()))
        missing = hub.runtime_switch("manager")["missing"]
        self.assertFalse(set(missing) & {"runtime_not_installed", "runtime_not_signed_in", "runtime_sign_in_unknown"})
        self.assertIs(hub.signed_in_now("manager", "codex"), True)

    def test_the_banner_follows_the_managers_own_report_without_a_tick(self):
        self.status(claude=False)
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "signed_out")
        self.status(claude=True)
        self.assertNotEqual(hub.kv_get("mgr_flag_kind"), "signed_out")

    # ---- what reaches the helpers
    def test_a_server_jobs_end_asks_a_helper_that_knows_the_kind_once(self):
        self.status()
        hub.status_now("manager")
        hub.status_now("manager")               # one waits unacknowledged: no second
        rows = hub.q("SELECT id FROM events WHERE agent='manager' AND kind='status_now'")
        self.assertEqual(len(rows), 1)
        hub.q("UPDATE events SET helper_ack=? WHERE id=?", (hub.now(), rows[0]["id"]))
        self.status(features=FEATURES)          # a helper from before the kind
        hub.status_now("manager")
        self.assertEqual(len(hub.q("SELECT id FROM events WHERE agent='manager' AND kind='status_now'")), 1)

    def test_a_sign_in_that_is_over_is_not_handed_out_again(self):
        over = hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('manager','claude',"
                       "'failed',?,?)", (hub.now(), hub.now()))
        running = hub.ins("INSERT INTO signin_jobs(agent,runtime,state,created,updated) VALUES('manager','claude',"
                          "'starting',?,?)", (hub.now(), hub.now()))
        for lid in (over, running):
            hub.emit("manager", "login", "Sign in to Claude Code", extra={"login": lid, "runtime": "claude"})
        events = self.poll()[1]["events"]
        self.assertEqual([e["extra"]["login"] for e in events if e["kind"] == "login"], [running])


if __name__ == "__main__":
    unittest.main()

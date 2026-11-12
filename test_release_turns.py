"""Plan P0 (AUTONOMY.md): releases and runtime switches wait for the turns that run now, not for open tasks.

The change rests on one fact, which `SessionSurvivesRestart` proves first with a real hub process: a session that is
between turns survives the hub's restart. Its MCP route is plain request and answer (`GET /mcp` is 405, so no stream
is open), the hub keeps no session state in memory (it gives an `Mcp-Session-Id` and never reads it back), and the
session's credential and the hub's generation are rows of the database, which a restart keeps. So the session's next
turn reaches the new process with the same address, the same credential and the same session id, as a client does
after its idle keep-alive connection was closed.

Run: python3 -m unittest -v test_release_turns.py
The rollback read against an older release: python3 test_release_turns.py --before <commit>
"""

import functools
import hashlib
import http.client
import json
import os
import re
import secrets
import select
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import fleet
import hub
import lifecycle
import releases
import test_releases
import usage
from test_releases import manifest
from test_ui_api import parent_pipe

KIT = os.path.dirname(os.path.abspath(__file__))
TEAM = {"hub": {"machine": "hub", "port": 8765},
        # One address for each machine (owner API 1.12). Every call of this test comes from 127.0.0.1, so it is vps's
        # machine: the agent alone on its address, which enrolls its key and gets its session credentials itself.
        "addresses": {"hub": "127.0.0.2", "vps": "127.0.0.1", "owner": "127.0.0.3"},
        "agents": {"manager": {"role": "manager", "machine": "hub", "runtime": "claude", "can": ["shell"]},
                   "vps": {"role": "worker", "machine": "vps", "runtime": "claude", "can": ["shell"]}}}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class McpClient:
    """One session's MCP client, as a runtime keeps it: one kept-alive connection, its route, its credential and the
    session id that `initialize` gave. Before each request it looks whether the idle connection was closed by the
    other end, and then opens a new one, as a pooling client does (urllib3's is_connection_dropped, undici's pool).
    `dropped` counts those."""

    def __init__(self, port, path, credential):
        self.port, self.path, self.credential = port, path, credential
        self.conn, self.session_id, self.dropped, self.next_id = None, None, 0, 0

    def connection(self):
        if self.conn is not None and self.conn.sock is not None and \
                select.select([self.conn.sock], [], [], 0)[0]:      # readable while idle: the other end closed it
            self.conn.close()
            self.conn = None
            self.dropped += 1
        if self.conn is None:
            self.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        return self.conn

    def post(self, method, params=None, notify=False):
        message = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            self.next_id += 1
            message["id"] = self.next_id
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": "Bearer " + self.credential}
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        conn = self.connection()
        conn.request("POST", self.path, body=json.dumps(message), headers=headers)
        response = conn.getresponse()
        body = response.read()
        if method == "initialize" and response.status == 200:
            self.session_id = response.getheader("Mcp-Session-Id")
        return response.status, (json.loads(body) if body else None)

    def call(self, name, **arguments):
        status, answer = self.post("tools/call", {"name": name, "arguments": arguments})
        if status != 200:
            return status, None, None
        result = answer.get("result") or {}
        return status, (result.get("content") or [{}])[0].get("text"), result.get("isError")

    def close(self):
        if self.conn is not None:
            self.conn.close()


class SessionSurvivesRestart(unittest.TestCase):
    """A real hub process, a task session that works one turn, the hub's restart between its turns, and the second
    turn of the same session on the new process."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fleet-turns-")
        self.addCleanup(lambda: subprocess.run(["rm", "-rf", self.tmp]))
        self.db = os.path.join(self.tmp, "pilot.db")
        self.team = os.path.join(self.tmp, "team.json")
        with open(self.team, "w") as f:
            json.dump(TEAM, f)
        self.port = free_port()
        self.proc = None
        self.addCleanup(self.stop)

    def start(self):
        pipe, fds = parent_pipe(self.tmp)
        self.proc = subprocess.Popen([sys.executable, os.path.join(KIT, "hub.py"), "--host", "127.0.0.1",
                                      "--port", str(self.port), "--db", self.db, "--team", self.team, "--tick", "1",
                                      "--parent-pipe", str(pipe)],
                                     pass_fds=fds, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     # a home of this test's own: ~/.fleet holds the owner's files of this machine
                                     env=dict(os.environ, HOME=self.tmp))
        for _ in range(100):
            try:
                if self.request("GET", "/health")[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        self.fail("the hub did not start")

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()               # what the service manager sends at a restart
            self.proc.wait(10)
        self.proc = None

    def request(self, method, path, body=None, key=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            headers = {"Content-Type": "application/json"}
            if key:
                headers["Authorization"] = "Bearer " + key
            conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
            response = conn.getresponse()
            data = response.read()
            return response.status, (json.loads(data) if data else None)
        finally:
            conn.close()

    def rows(self, sql, args=()):
        with sqlite3.connect(self.db, timeout=10) as db:
            db.row_factory = sqlite3.Row
            return [dict(r) for r in db.execute(sql, args)]

    def test_a_session_between_turns_survives_the_hubs_restart(self):
        self.start()
        generation = self.rows("SELECT v FROM kv WHERE k='db_id'")[0]["v"]
        key = secrets.token_urlsafe(32)
        code, said = self.request("POST", "/helper/key/vps", {"sha256": hashlib.sha256(key.encode()).hexdigest()})
        self.assertEqual(code, 200, said)
        # The manager's task, as create_task leaves it: the row and its first attempt.
        with sqlite3.connect(self.db, timeout=10) as db:
            t0 = time.time()
            task = db.execute("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt) "
                              "VALUES('Read the page','','the answer is in the result','none','vps','manager',"
                              "'submitted',?,1)", (t0,)).lastrowid
            db.execute("INSERT INTO attempts(task,attempt,created) VALUES(?,1,?)", (task, t0))
        # The helper's session credential for that attempt, and the session's own route.
        code, said = self.request("POST", "/helper/session/vps", {"kind": "task", "task": f"T-{task}", "attempt": 1,
                                                                  "generation": generation}, key=key)
        self.assertEqual(code, 200, said)
        session = McpClient(self.port, f"/mcp/vps/{generation}/T-{task}/1", said["token"])
        self.addCleanup(session.close)

        # The first turn.
        code, answer = session.post("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                   "clientInfo": {"name": "claude-code", "version": "test"}})
        self.assertEqual(code, 200, answer)
        self.assertTrue(session.session_id)
        self.assertEqual(session.post("notifications/initialized", notify=True)[0], 202)
        code, listed = session.post("tools/list")
        self.assertIn("report_progress", [t["name"] for t in listed["result"]["tools"]])
        self.assertEqual(session.call("report_progress", task_id=f"T-{task}", note="first turn")[1:], ("Noted.", False))
        self.assertEqual(session.dropped, 0)            # one kept-alive connection for the whole turn
        before = self.rows("SELECT sha256, revoked FROM session_credentials WHERE kind='task'")

        # Between turns: no call is open. The hub restarts.
        self.stop()
        self.start()

        # The second turn of the same session: same route, same credential, same session id.
        code, listed = session.post("tools/list")
        self.assertEqual(code, 200, listed)
        self.assertEqual(session.dropped, 1, "the old process closed the idle connection, and the client saw it")
        self.assertIn("report_progress", [t["name"] for t in listed["result"]["tools"]])
        self.assertEqual(session.call("report_progress", task_id=f"T-{task}", note="second turn")[1:], ("Noted.", False))
        self.assertEqual([n["text"] for n in self.rows("SELECT text FROM notes WHERE task=? ORDER BY id", (task,))],
                         ["first turn", "second turn"])
        self.assertEqual(self.rows("SELECT sha256, revoked FROM session_credentials WHERE kind='task'"), before)
        self.assertIsNone(before[0]["revoked"])
        self.assertEqual(self.rows("SELECT v FROM kv WHERE k='db_id'")[0]["v"], generation)
        self.assertEqual(self.rows("SELECT state, attempt FROM tasks WHERE id=?", (task,)),
                         [{"state": "working", "attempt": 1}])
        # The helper's own route goes on with the same generation, and its key.
        code, polled = self.request("GET", f"/events/vps?delivery=1&after=0&wait=0&alive=T-{task}", key=key)
        self.assertEqual((code, polled["db"]), (200, generation))


# ---- the facts a test gives the hub about a session, as a helper and a session's records give them

def windows(owner, *names):
    """The owner's helper checked in now, with this window list (plan C2)."""
    hub.touch(owner)
    hub.q("UPDATE agents SET alive=?, alive_ts=? WHERE name=?", (",".join(names), hub.now(), owner))


def turn(task, running):
    """The turn state of the task's current attempt, as its session's records leave it (plan C1): a turn that runs
    now, or one that ended."""
    attempt = hub.q1("SELECT attempt FROM tasks WHERE id=?", (task,))["attempt"]
    state = {"session": "0" * 8 + "-0000-4000-8000-" + "0" * 12, "seq": 4, "turns": 0 if running else 1,
             "running": running, "how": None if running else "end_turn", "at": hub.now(), "calls": {}, "said": None}
    hub.q("INSERT INTO attempts(task,attempt,created,turn) VALUES(?,?,?,?) ON CONFLICT(task,attempt) DO UPDATE SET "
          "turn=excluded.turn", (task, attempt, hub.now(), json.dumps(state)))


class Turns(test_releases.HubUpdates):
    """What an update and a runtime switch wait for, on the release fixture of test_releases.py."""

    def setUp(self):
        super().setUp()
        hub.CFG.setdefault("offline_after", 90)

    def delivered(self, kind, agent="vps"):
        """The tasks of the events of this kind that the agent's helper is given now."""
        code, data = self.request(f"/events/{agent}?delivery=1&after=0&wait=0", source=hub.address_of(agent))
        self.assertEqual(code, 200, data)
        return [e["task"] for e in data["events"] if e["kind"] == kind]

    def sent_check(self, agent="vps", state="sent"):
        rule = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,"
                       "max_tasks_per_day,anchor,created,updated,request_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                       (agent, "active", 1, json.dumps({"kind": "every", "minutes": 15}),
                        json.dumps({"path": "checks/queue.py", "commit": "c" * 40}), json.dumps({"title": "Look"}),
                        5, 1, hub.now(), hub.now(), hub.now(), "r-" + secrets.token_hex(4)))
        return hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,state,created) VALUES(?,1,?,?,?)",
                       (rule, hub.now(), state, hub.now()))

    def handed(self, agent="vps"):
        """One poll of the agent's helper: the conversation signals that its answer hands out, and its turns."""
        code, data = self.request(f"/events/{agent}?delivery=1&after=0&wait=0", source=hub.address_of(agent))
        self.assertEqual(code, 200, data)
        return [e["id"] for e in data["events"] if e["kind"] == "conversation"], data["turns"]

    def peer_writes(self):
        """A peer's message to vps, as person_route writes it: the message, its conversation's signal and the
        conversation task that it opens. The helper of vps is one of this tree, which sends no ack of a signal: it
        types it into the open window, or starts the window, and waits for the session's read. Only a Claude agent
        holds a conversation. These tests read a conversation with tools, which DevOps D5 and support plan F1 leave to
        no agent (test_contacts_v2.ShellOffRule): they run in the fleet before those rules."""
        reach = patch.object(hub, "contact_reach", lambda agent, person=None: True)
        reach.start()
        self.addCleanup(reach.stop)
        hub.TEAM["agents"]["vps"]["runtime"] = "claude"
        helper_reports("vps", *lifecycle.FEATURES)
        person = hub.ins("INSERT INTO people(name,role,added) VALUES('Bruno','peer',?)", (hub.now(),))
        hub.q("INSERT INTO person_agents(person,agent,added) VALUES(?,'vps',?)", (person, hub.now()))
        talk = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) "
                       "VALUES(?,?,?,?,?,?,?)", (person, "vps", "discord-1", "chat-1", "open", hub.now(), hub.now()))
        with hub.transaction():
            said = hub.DB.execute("INSERT INTO conversation_messages(conversation,who,text,created,event) "
                                  "VALUES(?,'person','Any news?',?,?)",
                                  (talk, hub.now(), hub.conversation_signal("vps", talk, hub.now()))).lastrowid
            task = hub.conversation_task_rows(hub.read_row("SELECT * FROM conversations WHERE id=?", (talk,)),
                                              hub.read_row("SELECT * FROM people WHERE id=?", (person,)), said,
                                              hub.now())
        return talk, task

    # ---- which turns count

    def test_a_session_between_turns_leaves_the_fleet_idle_and_a_running_turn_does_not(self):
        task = self.task_for()
        windows("vps", hub.tref(task))
        turn(task, running=False)
        self.assertEqual(hub.fleet_idle(), (True, []))
        state = self.releases_state()
        self.assertEqual((state["idle"], state["open_tasks"]), (True, []))
        turn(task, running=True)
        self.assertEqual(hub.fleet_idle(), (False, [task]))
        state = self.releases_state()
        self.assertEqual((state["idle"], state["open_tasks"]), (False, [task]))

    def test_a_session_that_reported_no_turn_yet_counts(self):
        """Its first turn runs, or its runtime reports none: the hub cannot tell, so it waits for it."""
        task = self.task_for()
        windows("vps", hub.tref(task))
        self.assertEqual(hub.fleet_idle(), (False, [task]))
        windows("vps", "owner-chat")            # no session of the task: nothing of it runs
        self.assertEqual(hub.fleet_idle(), (True, []))
        hub.kv_set("presence:vps", json.dumps({"step": "start", "task": hub.tref(task), "since": hub.now(),
                                               "at": hub.now()}))
        self.assertEqual(hub.fleet_idle(), (False, [task]))     # its helper is starting it now
        hub.kv_set("presence:vps", None)
        self.assertEqual(hub.fleet_idle(), (True, []))
        listed_at = hub.q1("SELECT alive_ts FROM agents WHERE name='vps'")["alive_ts"]
        hub.q("INSERT INTO session_credentials(sha256,agent,kind,generation,task,attempt,created) "
              "VALUES(?,?,?,?,?,?,?)", ("c" * 64, "vps", "task", "test-generation", task, 1, listed_at + 1))
        self.assertEqual(hub.fleet_idle(), (False, [task]))     # it took its credential after the helper's list
        hub.q("UPDATE agents SET alive_ts=? WHERE name='vps'", (listed_at + 2,))
        self.assertEqual(hub.fleet_idle(), (True, []))          # a newer list without its window: it is not there

    def test_a_turn_of_a_session_that_is_gone_or_of_an_offline_helper_does_not_count(self):
        task = self.task_for()
        turn(task, running=True)                # its last records said a turn runs
        windows("vps")                          # and then the window went
        self.assertEqual(hub.fleet_idle(), (True, []))
        windows("vps", hub.tref(task))
        self.assertEqual(hub.fleet_idle(), (False, [task]))
        hub.q("UPDATE agents SET last_seen=? WHERE name='vps'", (hub.now() - 3600,))
        with patch.object(hub, "STARTED", hub.now() - 7200):
            self.assertEqual(hub.fleet_idle(), (True, []))      # its helper went quiet an hour ago

    def test_without_a_window_list_an_open_task_counts_unless_its_turn_ended(self):
        task = self.task_for()
        hub.touch("vps")                        # online, but tmux gave no list
        self.assertEqual(hub.fleet_idle(), (False, [task]))
        turn(task, running=False)
        self.assertEqual(hub.fleet_idle(), (True, []))

    def test_a_check_run_with_its_helper_keeps_the_fleet_busy(self):
        windows("vps")
        run = self.sent_check(state="waiting")
        self.assertEqual(hub.fleet_idle(), (True, []))          # it waits for its helper: nothing runs yet
        hub.q("UPDATE trigger_runs SET state='sent' WHERE id=?", (run,))
        self.assertEqual(hub.fleet_idle(), (False, []))
        code, answer = self.press("update")
        self.assertEqual(code, 409, answer)
        self.assertIn("waits until no turn runs: a check runs now", answer["error"])
        hub.q("UPDATE agents SET last_seen=? WHERE name='vps'", (hub.now() - 3600,))
        self.assertEqual(hub.fleet_idle(), (True, []))          # an offline helper's run reaches nothing here

    def test_a_conversation_whose_signal_the_hub_holds_runs_no_turn(self):
        """A peer writes while the agent is at its usage limit, which holds the signal of the conversation's window
        until the reset, as settings that wait do: the conversation task of the message has no turn state, and its
        window stays open between turns, but nothing runs it (the review of 27 October 2026). The poll answer that
        hands the signal out counts the task, before the session reads it (the verifier of 28 October 2026)."""
        talk, task = self.peer_writes()
        hub.ins("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('vps',?,?,1)",
                (hub.now(), hub.now() + 4 * 86400))         # a weekly limit, four days before its reset
        windows("vps", f"C-{talk}")
        self.assertEqual(self.handed(), ([], []))
        self.assertEqual(hub.fleet_idle(), (True, []))
        hub.q("DELETE FROM agent_limits WHERE agent='vps'")     # the reset
        signals, turns = self.handed()      # the helper types it into the open window
        self.assertEqual((len(signals), turns), (1, [f"C-{talk}"]))
        self.assertEqual(hub.fleet_idle(), (False, [task]))
        turn(task, running=False)
        self.assertEqual(hub.fleet_idle(), (True, []))

    def test_a_conversation_window_that_starts_for_a_signal_runs_a_turn(self):
        """With no window of the conversation open, the helper that is handed the signal asks the hub for the start of
        C-<id>: the task counts from that start, before any record of its turn (the verifier of 28 October 2026)."""
        talk, task = self.peer_writes()
        windows("vps")
        self.assertEqual(len(self.handed()[0]), 1)
        code, start = self.request(f"/helper/conversations/vps/{talk}/start", {}, source=hub.address_of("vps"))
        self.assertEqual(code, 200, start)
        self.assertEqual(hub.fleet_idle(), (False, [task]))
        windows("vps", f"C-{talk}")
        turn(task, running=False)
        self.assertEqual(hub.fleet_idle(), (True, []))

    def screen(self, task, kind="shown", still=None, attempt=1):
        """The screen watch of vps's helper on the task's window, as it reports (runtime gaps C1)."""
        code, answer = self.request(f"/helper/dialog/vps/{hub.tref(task)}", fleet.screen_report(kind, attempt, still),
                                    source=hub.address_of("vps"))
        self.assertEqual(code, 200, answer)

    def test_a_session_that_stands_at_a_question_on_its_screen_runs_no_turn_until_a_record_moves(self):
        """Runtime gaps C1: a card in the middle of a turn leaves running_turns only while nothing moves. A "shown"
        report while its records keep moving keeps the task there (the coordinator's review, 29 October 2026): a
        screen's class is a guess, and a diff on a running screen can hold the words of a question."""
        task = self.task_for()
        windows("vps", hub.tref(task))
        turn(task, running=True)                    # the card came in the middle of a turn
        helper_reports("vps", hub.STUCK_SCREENS)
        self.screen(task, still=False)              # a record came since the question showed
        self.assertEqual(hub.fleet_idle(), (False, [task]))
        self.screen(task, still=True)
        self.assertEqual(hub.fleet_idle(), (True, []))
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (task,))["attempt"], 1)     # a turn runs
        said = json.loads(hub.kv_get(f"screen_question:{task}"))["at"]
        hub.q("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,1,?,9,?,?,?,?)",
              (task, "0" * 8 + "-0000-4000-8000-" + "0" * 12, said, "agent_message", '{"text": "on"}', said + 0.001))
        self.assertEqual(hub.fleet_idle(), (False, [task]))     # a record after that word: it moves after all
        self.screen(task, still=True, attempt=2)                # a word of another attempt's window changes nothing
        self.assertEqual(hub.fleet_idle(), (False, [task]))
        self.screen(task, "gone")
        self.screen(task, still=True)
        self.assertEqual(hub.fleet_idle(), (True, []))
        helper_reports("vps")                                   # a helper without the feature: as before
        self.screen(task, "gone")
        self.screen(task)
        self.assertEqual(hub.fleet_idle(), (False, [task]))

    # ---- the release

    def test_an_automatic_release_does_not_wait_for_a_session_that_stands_at_a_card(self):
        """Runtime gaps C1: one card on one screen kept every release of the fleet waiting until somebody answered
        it on that machine. The requester is told to start the task again."""
        self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
        working = self.task_for()
        windows("vps", hub.tref(working))
        turn(working, running=True)
        helper_reports("vps", hub.STUCK_SCREENS)
        self.screen(working, still=True)
        released = self.publish(self.code(2))
        with self.channel(manifest(released)), \
                patch.object(releases, "Update", functools.partial(releases.Update, run=self.runner())):
            hub.release_sweep(hub.now())
            self.finish()
        self.assertEqual(self.newest()["state"], releases.DONE)
        said = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say'")]
        self.assertTrue(any("restart_task (expected_attempt 1)" in t for t in said), said)

    def test_a_release_proceeds_while_a_parked_wake_and_a_conversation_wait_between_turns(self):
        wake = self.task_for()
        hub.ins("INSERT INTO reminders(due,note,agent,task,created) VALUES(?,?,?,?,?)",
                (hub.now() + 3600, "look again", "vps", wake, hub.now()))
        turn(wake, running=False)
        person = hub.ins("INSERT INTO people(name,role,added) VALUES('Ana','customer',?)", (hub.now(),))
        talk = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) "
                       "VALUES(?,?,?,?,?,?,?)", (person, "vps", "discord-1", "chat-1", "open", hub.now(), hub.now()))
        windows("vps", hub.tref(wake), f"C-{talk}")
        code, answer = self.run_update(self.publish(self.code(2)))
        self.assertEqual(code, 200, answer)
        self.assertEqual(self.newest()["state"], releases.DONE)
        self.assertIsNone(hub.release_waiting())

    def test_an_automatic_release_waits_for_a_running_turn_and_then_takes_the_first_quiet_moment(self):
        self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
        working = self.task_for()
        windows("vps", hub.tref(working))
        turn(working, running=True)
        released = self.publish(self.code(2))
        with self.channel(manifest(released)), \
                patch.object(releases, "Update", functools.partial(releases.Update, run=self.runner())):
            hub.release_sweep(hub.now())
            self.finish()
            self.assertEqual(self.newest()["state"], "verified")       # offered, not kept: it waits
            self.assertEqual(hub.release_waiting()["revision"], released)
            self.assertTrue(hub.release_holds_starts())
            later = self.task_for()
            self.assertEqual(self.delivered("task"), [], "a session started while a release waits")
            hub.release_sweep(hub.now())        # the turn still runs: a tick starts nothing
            self.finish()
            self.assertEqual(self.newest()["state"], "verified")
            turn(working, running=False)        # the turn ends
            hub.release_sweep(hub.now())        # the next tick takes it, past the poll's gate
            self.finish()
        self.assertEqual(self.newest()["state"], releases.DONE)
        self.assertIsNone(hub.release_waiting())
        self.assertFalse(hub.release_holds_starts())
        self.assertIn(hub.tref(later), self.delivered("task"))

    def test_a_waiting_release_holds_new_sessions_for_one_poll_time_only(self):
        """A turn that does not end cannot stop the fleet's new work: the release still waits, and holds nothing."""
        self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
        working = self.task_for()
        windows("vps", hub.tref(working))
        turn(working, running=True)
        released = self.publish(self.code(2))
        with self.channel(manifest(released)), \
                patch.object(releases, "Update", functools.partial(releases.Update, run=self.runner())):
            hub.release_sweep(hub.now())
            self.finish()
            later = self.task_for()
            self.assertEqual(self.delivered("task"), [])
            waits = hub.release_waiting()
            hub.kv_set("release_waits", json.dumps(dict(waits, since=waits["since"] - hub.RELEASE_POLL - 1)))
            self.assertFalse(hub.release_holds_starts())
            self.assertIn(hub.tref(later), self.delivered("task"))
            hub.release_sweep(hub.now() + hub.RELEASE_POLL + 1)     # the next poll finds the same release waiting
            self.finish()
            self.assertEqual(hub.release_waiting()["since"], waits["since"] - hub.RELEASE_POLL - 1)
            self.assertFalse(hub.release_holds_starts())

    def test_a_dutys_case_passes_the_wait_before_a_release_but_not_the_run(self):
        """DevOps plan V1: the work of a duty's case (a watch's wake, an outage) starts while a release waits for the
        turns that run now, and only the update run itself, whose end restarts the hub, holds it."""
        plain, case_task = self.task_for(), self.task_for()
        duty = hub.ins("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) "
                       "VALUES('vps','Answer each outage','active',1,?,?,'manager','r-duty')", (hub.now(), hub.now()))
        case = hub.ins("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by) "
                       "VALUES(?,'outage-1','The site is down','watch','open',?,'hub')", (duty, hub.now()))
        hub.q("UPDATE tasks SET duty_case=? WHERE id=?", (case, case_task))
        hub.kv_set("release_waits", json.dumps({"revision": "a" * 40, "since": hub.now()}))
        self.assertTrue(hub.release_holds_starts())
        self.assertEqual(self.delivered("task"), [hub.tref(case_task)])  # the plain task waits for the release
        with patch.object(hub, "release_applying", return_value=True):
            self.assertEqual(self.delivered("task"), [])                # the run holds every start
        hub.kv_set("release_waits", None)
        self.assertEqual(sorted(self.delivered("task")), sorted([hub.tref(plain), hub.tref(case_task)]))

    def test_a_release_the_run_would_refuse_does_not_wait(self):
        self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
        working = self.task_for()
        windows("vps", hub.tref(working))
        turn(working, running=True)
        released = self.publish(self.code(2))
        with self.channel(manifest(released, minimum="f" * 40)), \
                patch.object(releases, "Update", functools.partial(releases.Update, run=self.runner())):
            hub.release_sweep(hub.now())
            self.finish()
        one = self.newest()
        self.assertEqual((one["state"], one["step"]), (releases.KEPT, "minimum"))
        self.assertIsNone(hub.release_waiting())
        self.assertFalse(hub.release_holds_starts())
        with self.channel(manifest(released, version="2026.10.4", hold=True)):
            hub.release_sweep(hub.now() + hub.RELEASE_POLL + 1)
            self.finish()
        self.assertIsNone(hub.release_waiting())

    def test_a_failed_release_is_not_marked_kept_while_turns_run(self):
        """A row that a run already ended keeps what that run came to: the sweep tries it again when no turn runs."""
        self.assertEqual(self.press("entitlement", token=self.token())[0], 200)
        released = self.publish(self.code(2))
        broken = self.runner(selftest=(1, "FAIL one\n", ""))
        with self.channel(manifest(released)), patch.object(releases, "Update", functools.partial(releases.Update, run=broken)):
            hub.release_sweep(hub.now())
            self.finish()
            self.assertEqual(self.newest()["state"], releases.ROLLED_BACK)
            working = self.task_for()
            windows("vps", hub.tref(working))
            turn(working, running=True)
            hub.release_sweep(hub.now() + hub.RELEASE_POLL + 1)
            self.finish()
        self.assertEqual(self.newest()["state"], releases.ROLLED_BACK)
        self.assertIsNone(hub.release_waiting())

    def test_nothing_new_is_typed_into_a_session_during_the_run(self):
        """A session between turns stays between turns until the hub has restarted: a line would begin a turn."""
        parked = self.task_for()
        windows("vps", hub.tref(parked))
        turn(parked, running=False)
        checking, go = threading.Event(), threading.Event()
        table = self.runner()

        def run(argv, timeout=None, cwd=None, input=None):
            if argv[-1].endswith("selftest.py"):
                checking.set()
                go.wait(30)
            return table(argv, timeout=timeout, cwd=cwd, input=input)
        with self.channel(manifest(self.publish(self.code(2)))), \
                patch.object(releases, "Update", functools.partial(releases.Update, run=run)):
            self.assertEqual(self.press("update")[0], 200)
            self.assertTrue(checking.wait(60), "the run never reached its checks")
            hub.emit("vps", "say", "[hub] a message for the parked task", task=parked)
            self.assertEqual(self.delivered("say"), [])
            go.set()
            self.finish()
        self.assertEqual(self.newest()["state"], releases.DONE)
        self.assertEqual(self.delivered("say"), [hub.tref(parked)])

    # ---- the helper's own update (helper feature update_between_turns)

    def poll(self, agent="vps"):
        code, data = self.request(f"/events/{agent}?delivery=1&after=0&wait=0", source=hub.address_of(agent))
        self.assertEqual(code, 200, data)
        return data

    def test_a_helper_that_updates_between_turns_gets_the_turns_that_run_in_its_windows(self):
        task = self.task_for()
        windows("vps", hub.tref(task))
        turn(task, running=True)
        self.assertIsNone(self.poll()["turns"])                 # a helper without the feature: no reading
        helper_reports("vps", "update_between_turns")
        self.assertEqual(self.poll()["turns"], [hub.tref(task)])
        turn(task, running=False)
        self.assertEqual(self.poll()["turns"], [])               # parked between turns: the helper may update

    def test_the_poll_names_a_workers_open_tasks_and_none_for_the_manager(self):
        """4 November 2026: each task works in its own clones, which its helper deletes once the task is not open."""
        task = self.task_for()
        self.assertEqual(self.poll()["open_tasks"], [hub.tref(task)])
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (task,))
        self.assertEqual(self.poll()["open_tasks"], [])
        self.assertIsNone(self.poll(hub.manager_name())["open_tasks"])

    # ---- the runtime switch

    def test_a_switch_waits_for_running_turns_and_check_runs_in_flight_only(self):
        task = self.task_for()
        windows("vps", hub.tref(task))
        turn(task, running=False)
        self.assertIsNone(hub.switch_busy("vps"))
        turn(task, running=True)
        self.assertEqual(hub.switch_busy("vps")["open_tasks"], [hub.tref(task)])
        turn(task, running=False)
        run = self.sent_check(state="waiting")
        self.assertIsNone(hub.switch_busy("vps"))               # a run that waits for its helper runs nothing yet
        hub.q("UPDATE trigger_runs SET state='sent' WHERE id=?", (run,))
        self.assertEqual(hub.switch_busy("vps")["checks"], [run])


class HelperUpdate(unittest.TestCase):
    """Plan P0: a helper takes its own Fleet update while its task sessions are between turns. A session parked
    between turns survives the helper's restart and the update of its checkout, and the new helper types its next
    line: proven on 27 October 2026 with the real helper, a real Claude Code 2.1.311 and Codex 0.163 window, a real
    hub and a scripted stand-in model (COORDINATION.md, "Readiness"). These are the helper's own rules, with stand-in
    windows and screens."""

    def setUp(self):
        self.helper = fleet.Helper("vps", {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]})
        self.windows, self.runners, self.screens = ["home", "owner-chat"], set(), set()
        for p in (patch.object(self.helper, "look_known", side_effect=lambda: self.windows),
                  patch.object(self.helper, "runner", side_effect=lambda t: t.split(":=")[1] in self.runners),
                  patch.object(self.helper, "working", side_effect=lambda t: t.split(":=")[1] in self.screens)):
            p.start()
            self.addCleanup(p.stop)

    def test_a_task_window_waits_while_the_hub_gives_no_reading(self):
        self.assertFalse(self.helper.update_busy())             # no task window: it never waited for the others
        self.windows = ["owner-chat", "T-1"]
        self.assertTrue(self.helper.update_busy())              # an older hub, or a poll that failed: as before

    def test_sessions_between_turns_let_the_update_go(self):
        self.windows = ["owner-chat", "T-1", "T-2"]
        self.helper.hub_turns = (set(), time.monotonic())
        self.assertFalse(self.helper.update_busy())

    def test_a_turn_that_runs_keeps_the_update_waiting(self):
        self.windows = ["T-1", "T-2"]
        read = time.monotonic()
        cases = {"the hub reads a turn in it": lambda: setattr(self.helper, "hub_turns", ({"T-2"}, read)),
                 "a line went in after the reading": lambda: self.helper.typed_at.update({"T-1": read + 1}),
                 "its screen shows a turn": lambda: self.screens.add("T-1"),
                 "it runs in the runner": lambda: self.runners.add("T-2"),
                 "tmux gives no list": lambda: setattr(self, "windows", None),
                 "a check or a login job runs": lambda: setattr(self.helper, "outside", 1)}
        for case, make in cases.items():
            with self.subTest(case):
                self.helper.hub_turns, self.helper.outside, self.windows = (set(), read), 0, ["T-1", "T-2"]
                self.helper.typed_at.clear(), self.screens.clear(), self.runners.clear()
                self.assertFalse(self.helper.update_busy())
                make()
                self.assertTrue(self.helper.update_busy())

    def test_a_line_typed_before_the_reading_is_in_it(self):
        self.windows = ["T-1"]
        self.helper.typed_at["T-1"] = time.monotonic()
        self.helper.hub_turns = (set(), time.monotonic() + 1)
        self.assertFalse(self.helper.update_busy())


# ---- the rollback reads: what the later lanes of AUTONOMY.md write (section 6.1), as they would write it

# The columns of AUTONOMY.md 6.1 that a release adds in migrate: a later lane's release has them already, so each is
# added only where the database lacks it, and the same rows load on the previous release and on the lane's own.
LATER_COLUMNS = (("tasks", "source_conversation", "INTEGER"), ("tasks", "source_message", "INTEGER"),
                 ("conversation_messages", "task", "INTEGER"), ("conversation_messages", "waits", "INTEGER"),
                 # lane L4's
                 ("trigger_history", "saved_by_task", "INTEGER"), ("trigger_history", "outside_reads", "INTEGER"),
                 ("trigger_runs", "lines", "TEXT"), ("trigger_runs", "runs", "INTEGER"),
                 ("events", "handed", "REAL"),          # plan P0: the poll answer that handed out a signal
                 # questions up the line (29 October 2026): who passed a question up, who answered it, and the
                 # Needs-you item that took it to the owner
                 ("questions", "passed", "TEXT"), ("questions", "answered_by", "TEXT"), ("needs", "question", "INTEGER"),
                 ("duty_cases", "opened_in", "INTEGER"),     # one event, one case (3 November 2026)
                 ("tasks", "scope_person", "INTEGER"))       # the person access plan (11 November 2026)
LATER = """
CREATE TABLE IF NOT EXISTS person_scopes(person INTEGER NOT NULL, agent TEXT NOT NULL, grants TEXT NOT NULL,
  updated REAL NOT NULL, PRIMARY KEY(person, agent));
CREATE TABLE IF NOT EXISTS duty_joins(duty_case INTEGER NOT NULL, responsibility INTEGER NOT NULL, ts REAL NOT NULL,
  PRIMARY KEY(duty_case, responsibility));
CREATE TABLE IF NOT EXISTS roles(name TEXT PRIMARY KEY, prompt TEXT NOT NULL, tools INTEGER NOT NULL, daily INTEGER,
  created REAL NOT NULL, updated REAL NOT NULL);
CREATE TABLE IF NOT EXISTS standing(id INTEGER PRIMARY KEY, agent TEXT NOT NULL, scope TEXT NOT NULL,
  kind TEXT NOT NULL, words TEXT NOT NULL, measure TEXT, number REAL, due REAL, how TEXT, "check" INTEGER,
  progress REAL, author_kind TEXT NOT NULL, author TEXT NOT NULL, conversation INTEGER, message INTEGER,
  created REAL NOT NULL, ended REAL, ended_by TEXT, ended_why TEXT);
CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, agent TEXT NOT NULL, kind TEXT NOT NULL, ref TEXT NOT NULL,
  person TEXT, task INTEGER, at REAL NOT NULL, owner_chat INTEGER NOT NULL DEFAULT 0, src TEXT NOT NULL,
  src_id INTEGER, text TEXT);
CREATE INDEX IF NOT EXISTS history_agent_at ON history(agent, at);
CREATE INDEX IF NOT EXISTS history_of_task ON history(task, at) WHERE task IS NOT NULL;
CREATE INDEX IF NOT EXISTS history_of_person ON history(person, at) WHERE person IS NOT NULL;
CREATE INDEX IF NOT EXISTS history_of_ref ON history(ref, agent) WHERE kind<>'tool';
CREATE VIRTUAL TABLE IF NOT EXISTS history_fts USING fts5(text, agent, content='',
  tokenize='unicode61 remove_diacritics 2');
CREATE INDEX IF NOT EXISTS task_delivered ON tasks(delivered) WHERE delivered IS NOT NULL;
CREATE INDEX IF NOT EXISTS task_checked ON tasks(checked_at) WHERE checked_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS question_answered ON questions(answered) WHERE answered IS NOT NULL;
CREATE INDEX IF NOT EXISTS report_decided ON reports(decided) WHERE decided IS NOT NULL;
CREATE INDEX IF NOT EXISTS memory_dropped ON memories(dropped) WHERE dropped IS NOT NULL;
CREATE TABLE IF NOT EXISTS model_changes(id INTEGER PRIMARY KEY, agent TEXT NOT NULL, by TEXT NOT NULL, "from" TEXT,
  "to" TEXT, why TEXT, at REAL NOT NULL);
"""
LATER_TEAM = {"hub": {"machine": "hub", "port": 8765},
              "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "vps": "127.0.0.3"},
              "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                         "vps": {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]}},
              # AUTONOMY.md section 4: settings that later releases keep in team.json
              "settings": {"contacts.v2": True, "session_reuse": {"on": True, "growth": 2, "margin": 60}},
              "runtime_facts": {"claude": {"cache_seconds": 300}}}
LINES_CHECK = {"form": "lines", "code": "saved", "sha256": "a" * 64, "bytes": 10, "code_by": "vps",
               "args": {}, "timeout_seconds": 60}
UNKNOWN_CHECK = dict(LINES_CHECK, form="no-release-knows-this")     # a form that no release reads
SAVED = "bws://aaaaaaaa-1111-4222-8333-444444444444"     # the login that a waiting task's owner saved


def later_data(t0=None):
    """Into hub.DB: the schema additions of AUTONOMY.md 6.1 and one row of each new value, as the later lanes would
    write them. A lane that ships its own writes changes its rows here to what its code writes. Returns their ids."""
    t0 = t0 or hub.now()
    for table, column, kind in LATER_COLUMNS:
        if column not in {r["name"] for r in hub.q(f"PRAGMA table_info({table})")}:
            hub.q(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
    hub.DB.executescript(LATER)
    for table, column, kind in LATER_COLUMNS:
        if column not in {r["name"] for r in hub.q(f"PRAGMA table_info({table})")}:
            hub.q(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
    made = {"peer": hub.ins("INSERT INTO people(name,role,added) VALUES('Bruno','peer',?)", (t0,)),
            "boss": hub.ins("INSERT INTO people(name,role,note,added) VALUES('Angela','manager','billing',?)", (t0,)),
            # lane L1: a customer, and a role that no release knows (an owner's role that was deleted since)
            "customer": hub.ins("INSERT INTO people(name,role,added) VALUES('Ana','customer',?)", (t0,)),
            "stranger": hub.ins("INSERT INTO people(name,role,added) VALUES('Lucia','auditor',?)", (t0,))}
    for person in (made["peer"], made["boss"]):
        hub.q("INSERT INTO person_agents(person,agent,added) VALUES(?,?,?)", (person, "vps", t0))
    # the person access plan: a narrowed pair that no other assertion here uses (the stranger on studio), as the
    # owner's write keeps it, and its conversation task, which carries the person from birth
    hub.q("INSERT INTO person_scopes(person,agent,grants,updated) VALUES(?,?,?,?)",
          (made["stranger"], "studio", json.dumps({"repo:acme/crm": "write"}), t0))
    made["narrowed"] = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,"
                               "last_activity,stop_sent,why,attempt,scope_person) VALUES('Answer Lucia','A conversation "
                               "task.','studio answered with reply.','none','studio','manager','completed',?,?,1,"
                               "'Lucia wrote.',1,?)", (t0, t0, made["stranger"]))
    made["talk"] = hub.ins("INSERT INTO conversations(person,agent,account,chat,state,created,last) "
                           "VALUES(?,?,?,?,?,?,?)", (made["peer"], "vps", "discord-1", "c1", "open", t0, t0))
    # lane L2 (AUTONOMY.md P2), as its own code writes them: the peer's message, the conversation task that it opened
    # (hub.conversation_task_rows: its message, no start event, its stop never sent), the task that open_work opened
    # from it, a line that the hub wrote into the conversation (a result), and an agent's message_contact that waits
    made["said"] = hub.ins("INSERT INTO conversation_messages(conversation,who,text,created,event) VALUES(?,?,?,?,NULL)",
                           (made["talk"], "person", "Can you fix the export?", t0))
    made["task"] = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,last_activity,"
                           "stop_sent,source_conversation,source_message,why,attempt) VALUES('Answer the peer in C-1',"
                           "'A conversation task.','vps answered with reply.','none','vps','manager','working',"
                           "?,?,1,?,?,'The peer wrote in C-1.',1)", (t0, t0, made["talk"], made["said"]))
    hub.q("INSERT INTO attempts(task,attempt,created,reason) VALUES(?,1,?,'created')", (made["task"], t0))
    hub.q("UPDATE conversation_messages SET task=? WHERE id=?", (made["task"], made["said"]))
    made["work"] = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt,"
                           "source_conversation) VALUES('Fix the export','From C-1.','The work is done.','none','vps',"
                           "'manager','working',?,1,?)", (t0, made["talk"]))
    hub.q("INSERT INTO conversation_messages(conversation,who,text,created,task) VALUES(?,'action',?,?,?)",
          (made["talk"], f"Opened work: Fix the export (T-{made['work']})", t0, made["work"]))
    hub.q("INSERT INTO conversation_messages(conversation,who,text,created,task,event) VALUES(?,'action',?,?,?,NULL)",
          (made["talk"], f"T-{made['work']} (Fix the export) is completed: fixed", t0, made["work"]))
    hub.q("INSERT INTO conversation_messages(conversation,who,text,created,task,waits) VALUES(?,'agent',?,?,?,?)",
          (made["talk"], "Shall I deploy it now?", t0, made["work"], made["work"]))
    # plan P0: the signal of Bruno's message, which a poll answer handed out to the helper (events.handed)
    signal = hub.ins("INSERT INTO events(agent,kind,text,created,extra,handed) VALUES('vps','conversation',?,?,?,?)",
                     (f"New message in conversation C-{made['talk']}.", t0,
                      json.dumps({"conversation": made["talk"], "generation": "test-generation"}), t0))
    hub.q("UPDATE conversation_messages SET event=? WHERE id=?", (signal, made["said"]))
    # and the id floors that a person's removal keeps (hub.unused_id), above every id given out
    for table in ("conversations", "conversation_messages"):
        hub.q("INSERT INTO kv(k,v) VALUES(?,'90') ON CONFLICT(k) DO UPDATE SET v=excluded.v", (f"row_floor:{table}",))
    # lane L6 (AUTONOMY.md P7), as hub.t_remember, hub.memory_from_work and hub.duty_review_rows write them: no new
    # column. A lesson written again in place of one that it removed (the old one in the dropped columns, which every
    # release hides), what did not work as an ordinary lesson, two lessons that the work wrote close to each other
    # (kv, in the shape of hub.memory_close_rows: the older release that runs this has no such function), and a
    # review's record of what it listed.
    old = hub.ins("INSERT INTO memories(agent,about,text,prevents,created,request_id,dropped,dropped_by,drop_reason) "
                  "VALUES('vps','crm','an old lesson','a wrong reply',?,'m-1',?,'vps','written again as M-2')",
                  (t0, t0))
    now_reads = hub.ins("INSERT INTO memories(agent,about,text,prevents,created,by_task,request_id) VALUES('vps','crm',"
                        "'the lesson as it reads now','a wrong reply',?,?,'m-2')", (t0, made["task"]))
    tried = hub.ins("INSERT INTO memories(agent,about,text,prevents,created,by_task,request_id) VALUES('vps','crm',"
                    "'What did not work: the CRM export of a closed ticket. To check: export one.',"
                    "'paying for this dead end a second time',?,?,'')", (t0, made["task"]))
    for key, value in (("memory_close:vps", [[now_reads, tried]]),
                       ("duty_review:vps", {"at": t0, "seen": [], "task": made["task"],
                                            "lessons": [f"M-{old}:s", f"M-{now_reads}+M-{tried}"]})):
        hub.q("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, json.dumps(value)))
    hub.q("INSERT INTO reports(from_agent,to_agent,kind,text,severity,delivered,created,request_id) "
          "VALUES('vps','manager','proposal','Buy a second account','note','note',?,'r-1')", (t0,))
    # lane L1: the three default roles (OR IGNORE: a release with the roles table seeds its own) and one of the owner's
    for name, prompt, tools, daily in (("customer", "An outsider.", 0, 30), ("peer", "A colleague.", 1, None),
                                       ("manager", "A colleague above you.", 1, None),
                                       ("supplier", "A supplier of the shop.", 0, 10)):
        hub.q("INSERT OR IGNORE INTO roles(name,prompt,tools,daily,created,updated) VALUES(?,?,?,?,?,?)",
              (name, prompt, tools, daily, t0, t0))
    hub.q("INSERT OR IGNORE INTO kv(k,v) VALUES('contacts_v2_roles',?)", (str(t0),))
    # Lane L3's rows as its own code writes them (hub.standing_new_rows, standing_end_rows): a person's instruction,
    # the owner's target that a check measures, the owner's instruction for the fleet manager's team, and an item
    # that has ended.
    hub.q("INSERT INTO standing(agent,scope,kind,words,author_kind,author,conversation,message,created) "
          "VALUES('vps','agent','instruction','fix the export',?,?,?,?,?)",
          ("person", f"P-{made['peer']}", made["talk"], made["said"], t0))
    hub.q("INSERT INTO standing(agent,scope,kind,words,measure,number,due,how,progress,author_kind,author,message,"
          "created) VALUES('vps','agent','target','first draft within 2 hours for 90% of tickets',"
          "'tickets with a first draft within 2 hours, in percent',90,?,'the CRM ticket times',87,'owner','owner',7,?)",
          (t0 + 30 * 86400, t0))
    hub.q("INSERT INTO standing(agent,scope,kind,words,author_kind,author,message,created) VALUES('manager','team',"
          "'instruction','refunds go to Maria','owner','owner',8,?)", (t0,))
    hub.q("INSERT INTO standing(agent,scope,kind,words,author_kind,author,created,ended,ended_by,ended_why) "
          "VALUES('vps','agent','instruction','answer in Spanish','agent','vps',?,?,'owner','the owner ended it')",
          (t0, t0))
    # what a conversation window was told of, as hub.standing_pull counts it: {item id: standing_digest}
    hub.q("INSERT INTO kv(k,v) VALUES(?,?)", (f"standing_told:{made['talk']}", '{"1": "0123456789abcdef"}'))
    # lane L5 (AUTONOMY.md P6), as hub.history_step writes them: the record's row, its words in the index under the
    # agent's key, the key itself, and the cursor of its stream
    made["history"] = hub.ins("INSERT INTO history(agent,kind,ref,person,task,at,owner_chat,src,src_id,text) "
                              "VALUES('vps','conversation',?,?,?,?,0,'conversation',?,"
                              "'Bruno: Can you fix the export?')",
                              (f"CM-{made['said']}", f"P-{made['peer']}", made["task"], t0, made["said"]))
    hub.q("INSERT INTO history_fts(rowid,text,agent) VALUES(?,'Bruno: Can you fix the export?','a1')",
          (made["history"],))
    for key, value in (("history_agent:vps", "1"), ("history_agent_count", "1"),
                       ("history:conversation", str(made["said"]))):
        hub.q("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
    # lane L7 (AUTONOMY.md P8), as hub.t_set_agent_model and hub.record_session_tokens write them. Its release adds
    # the columns of session_tokens, so a database it wrote has them before an older release reads it.
    for column, kind in (("input", "INTEGER"), ("cache_read", "INTEGER"), ("cache_write", "INTEGER"),
                         ("output", "INTEGER"), ("calls", "INTEGER"), ("kind", "TEXT"), ("task_kind", "TEXT"),
                         ("model", "TEXT"), ("runtime", "TEXT"), ("account", "TEXT"), ("first_cache_share", "REAL"),
                         ("window_share", "REAL"), ("models", "TEXT")):
        if column not in {r["name"] for r in hub.q("PRAGMA table_info(session_tokens)")}:
            hub.q(f"ALTER TABLE session_tokens ADD COLUMN {column} {kind}")
    hub.q("INSERT INTO model_changes(agent,by,\"from\",\"to\",why,at) VALUES('vps','manager',?,?,'routine work',?)",
          (json.dumps({"model": "claude-opus-5-5", "effort": None}),
           json.dumps({"model": "claude-sonnet-5-5", "effort": "low"}), t0))
    # helper feature session_models: a session's tokens by model, a workflow agent's on Haiku among them
    models = json.dumps([["claude-sonnet-5-5", 60, 800, 50, 40, 4], ["claude-haiku-5-5", 40, 0, 0, 10, 2]])
    for sid, kind, task_kind in (("s-1", "conversation", "conversation"), ("s-2", "case", "R-1"),
                                 ("s-3", "standing", None)):
        hub.q("INSERT INTO session_tokens(agent,session_id,total,last_activity,reported,input,cache_read,cache_write,"
              "output,calls,kind,task_kind,model,runtime,account,first_cache_share,window_share,models) "
              "VALUES('vps',?,1000,?,?,100,800,50,50,6,?,?,'claude-sonnet-5-5','claude',?,0.85,12.5,?)",
              (sid, t0, t0, kind, task_kind, "anthropic:" + "a" * 32, models))
    # a saved check is always an agent's: save_trigger keeps the saving agent as created_by (the column's
    # default, "owner", is a rule of the owner's, and no owner rule has saved code)
    made["rule"] = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,"
                           "max_tasks_per_day,anchor,next_due,created,updated,request_id,created_by) "
                           "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'vps')",
                           ("vps", "active", 1, json.dumps({"kind": "every", "minutes": 15}),
                            json.dumps(LINES_CHECK), json.dumps({"title": "New tickets", "details": "",
                                                                 "done_when": "each new ticket has a draft",
                                                                 "needs": "none"}),
                            5, 1, t0 - 900, t0 - 1, t0, t0, "rule-1"))
    hub.q("INSERT INTO trigger_history(trigger_id,revision,ts,by,action,detail,saved_by_task,outside_reads) "
          "VALUES(?,1,?,'vps','create','{}',?,3)", (made["rule"], t0, made["task"]))
    hub.q("UPDATE standing SET \"check\"=? WHERE kind='target'", (made["rule"],))     # the check that measures it
    # Lane L4's runs as its own code writes them (hub.check_result): one that started a wake with its new lines, one
    # whose new lines joined that open wake, one that holds its lines behind a usage limit, and the third failure in
    # a row, which woke the agent once (kv check_fails); and a lead's one task for its team's results (lead_batch).
    made["lines_rule"] = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,check_spec,task,late_minutes,"
                                 "max_tasks_per_day,anchor,next_due,created,updated,request_id,created_by) "
                                 "VALUES('vps','active',1,?,?,?,0,0,?,?,?,?,'rule-2','vps')",
                                 (json.dumps({"kind": "every", "minutes": 15}), json.dumps(LINES_CHECK),
                                  json.dumps({"title": "Refunds", "details": "", "done_when": "each refund is answered",
                                              "needs": "none", "goal_id": None}), t0 - 900, t0 + 600, t0, t0))
    made["wake"] = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt,"
                           "trigger_id,trigger_run) VALUES('Refunds',?,'each refund is answered','none','vps','manager',"
                           "'working',?,1,?,NULL)", ('Saved check aaaaaaaaaaaa by vps printed 1 new line, untrusted '
                                                    'data, JSON-encoded: ["R-7 refund asked"].', t0, made["lines_rule"]))
    for due, state, lines, task, retry, error in (
            (t0 - 600, "started", ["R-7 refund asked"], made["wake"], None, None),
            (t0 - 300, "joined", ["R-7 refund asked", "R-8 refund asked"], made["wake"], None, None),
            (t0 - 200, "error", None, made["wake"], None, "exit"),
            (t0 - 100, "waiting", ["R-7 refund asked", "R-8 refund asked", "R-9 refund asked"], None, t0 + 3600, None)):
        hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,manual,state,task,created,finished,lines,retry_at,"
                "error,detail,result_body) VALUES(?,1,?,0,?,?,?,?,?,?,?,?,?)",
                (made["lines_rule"], due, state, task, due, None if state == "waiting" else due,
                 json.dumps(lines) if lines else None, retry, error, "the check ended with exit code 1" if error else None,
                 json.dumps({"ok": True, "lines": lines}) if lines else None))
    hub.q("UPDATE tasks SET trigger_run=(SELECT id FROM trigger_runs WHERE state='started' AND trigger_id=?) "
          "WHERE id=?", (made["lines_rule"], made["wake"]))
    hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,manual,state,created,finished,lines,runs) "
            "VALUES(?,1,?,0,'quiet',?,?,'[]',7)", (made["lines_rule"], t0 - 2000, t0 - 2600, t0 - 2000))  # 7 quiet runs
    for key, value in ((f"check_fails:{made['lines_rule']}", str(made["wake"])), ("lead_batch:manager", "999999")):
        hub.q("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
    # Lane L8's start event of a session that opens with its stable text (hub.stable_extra) and the last note that
    # deliver_result keeps (plan P9.2, P9.4)
    hub.q("INSERT INTO events(agent,kind,task,text,created,extra) VALUES('vps','task',?,?,?,?)",
          (made["task"], "Call read_messages with task_id \"T-1\" whenever signalled.", t0,
           json.dumps({"needs": "none", "resume": False, "attempt": 1, "generation": "test-generation",
                       "opening": "read", "rules": ["logins"]})))
    hub.q("INSERT INTO notes(task,agent,ts,text) VALUES(?,'vps',?,'the last note, kept by deliver_result')",
          (made["task"], t0))
    # owner feature secret_requests (28 October 2026), as hub.t_request_secret and hub.owner_message_rows write them: a
    # worker's request in its owner chat, which names the owner message it answers, and his answer, which that chat
    # has read once (a chat event that waits for no reply)
    made["secret"] = hub.ins("INSERT INTO needs(title,why,todo,raised,by,kind,secret,answer,answered) VALUES("
                             "'Enter a login for app.ahrefs.com','The owner wants backlinks.','Open this request.',?,"
                             "'vps','secret',?,'Saved the login.',?)",
                             (t0, json.dumps({"kind": "login", "site": "https://app.ahrefs.com/login",
                                              "give": {"vps": "use"}, "reply": "r-secret",
                                              "saved": "bws://aaaaaaaa-1111-4222-8333-444444444444"}), t0))
    made["secret_answer"] = hub.ins(
        "INSERT INTO events(agent,kind,text,created,extra,read_at) VALUES('vps','chat',?,?,?,?)",
        (f"[owner] Answer to Needs-you N-{made['secret']} (Enter a login for app.ahrefs.com): Saved the login. It needs "
         f"no reply.", t0, json.dumps({"generation": "test-generation", "need": made["secret"]}), t0))
    hub.q("INSERT INTO ui_requests(request_id,kind,need_id,text,event_id,created,client,recipient) "
          "VALUES('a-secret','answer',?,'Saved the login.',?,?,'test','vps')", (made["secret"], made["secret_answer"], t0))
    # runtime gaps C1 (29 October 2026), as hub.helper_dialog and hub.screen_attempt write them: a question that stands
    # on the screen of a task's session, its usage-limit menu, and the one new attempt that such a question gave a task
    made["screen"] = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,created,attempt) "
                             "VALUES('Read the logs','A task.','The logs are read.','none','vps','manager',"
                             "'working',?,2)", (t0,))
    hub.q("INSERT INTO attempts(task,attempt,created,reason,ended) VALUES(?,1,?,'created',?)", (made["screen"], t0, t0))
    hub.q("INSERT INTO attempts(task,attempt,created,reason) VALUES(?,2,?,'screen question')", (made["screen"], t0))
    for key, value in ((f"screen_question:{made['screen']}", json.dumps({"attempt": 2, "at": t0, "still": True})),
                       (f"screen_limit:{made['screen']}", "2"), (f"screen_restart:{made['screen']}", "2")):
        hub.q("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
    # Questions up the line (29 October 2026), as hub.pass_question, hub.answer_rows, hub.t_raise_needs_you,
    # hub.question_needs_close, hub.chat_result and hub.lead_unread_sweep write them: a question that a lead passed up
    # and the manager holds now, the Needs-you item that takes it to the owner, a question that the owner answered
    # through such an item and the item that the hub closed when another level answered first, the result of a task
    # that an owner chat opened, which that chat read, and the manager's note of what a lead left unread.
    made["passed"] = hub.ins("INSERT INTO questions(task,asker,requester,text,asked,passed) VALUES(?,'vps','manager',"
                             "'Blue or green?',?,'[\"lead\"]')", (made["work"], t0))
    hub.q("INSERT INTO needs(title,why,todo,raised,by,question) VALUES('Which colour?','Quoting vps (Q-1): \"Blue or "
          "green?\"','Say blue or green',?,'manager',?)", (t0, made["passed"]))
    answered = hub.ins("INSERT INTO questions(task,asker,requester,text,asked,answer,answered,passed,answered_by) "
                       "VALUES(?,'vps','manager','Which font?',?,'Serif.',?,'[\"lead\"]','owner')",
                       (made["work"], t0, t0))
    hub.q("INSERT INTO needs(title,why,todo,raised,by,question,answer,answered,answered_by) VALUES('Which font?','x',"
          "'Say it',?,'manager',?,'Closed: Q-2 was answered by lead: Serif.',?,'Fleet')", (t0, answered, t0))
    hub.q("INSERT INTO events(agent,kind,text,created,extra,read_at) VALUES('vps','chat',?,?,?,?)",
          (f"[hub] T-{made['work']} (Fix the export), which you opened from the owner's message a-1 in this chat, is "
           f"completed: fixed", t0, json.dumps({"generation": "test-generation", "task_result": made["work"]}), t0))
    hub.q("INSERT INTO kv(k,v) VALUES(?,'1') ON CONFLICT(k) DO UPDATE SET v=excluded.v", ("lead_unread:stuck:1:1",))
    # and, from 29 October 2026, as hub.t_request_secret writes them for a task session: a task that waits on its open
    # request, and a task that waits for the secret that the owner saved to reach its machine (a delivery on its way)
    made["asking"] = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,waiting_on,created,"
                             "attempt) VALUES('Read the backlinks','From the owner.','listed','none','vps','manager',"
                             "'input-required','N-91',?,1)", (t0,))
    made["saved"] = hub.ins("INSERT INTO tasks(title,details,done_when,needs,owner,requester,state,waiting_on,created,"
                            "attempt) VALUES('Read the rankings','From the owner.','listed','none','vps','manager',"
                            "'input-required','N-92',?,1)", (t0,))
    for nid, task, answer, extra in ((91, made["asking"], None, {}),
                                     (92, made["saved"], "Saved the login.", {"saved": SAVED})):
        hub.q("INSERT INTO needs(id,title,why,todo,raised,by,kind,secret,answer,answered) VALUES(?,?,?,?,?,?,?,?,?,?)",
              (nid, "Enter a login for app.ahrefs.com", "The task reads backlinks.", "Open this request.", t0, "vps",
               "secret", json.dumps(dict({"kind": "login", "site": "https://app.ahrefs.com/login",
                                          "give": {"vps": "use"}, "tasks": [task]}, **extra)), answer,
               t0 if answer else None))
    hub.q("INSERT INTO deposits(login,machine,agent,recipient,sha256,request_id,created) VALUES(?,?,?,?,?,?,?)",
          (SAVED, "vps", "vps", "age1later", "0" * 64, "d-later", t0))
    # One event, one case (3 November 2026), as hub.t_open_case writes them: two cases that one task opened, so it
    # carries neither, and another duty that joined the first of them, with the line of its history that says so
    duty = "INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) " \
           "VALUES('vps',?,'active',1,?,?,'vps',?)"
    made["duty"] = hub.ins(duty, ("Find each advisory that touches the shop.", t0, t0, "r-advisories"))
    made["joiner"] = hub.ins(duty, ("Fix the advisories of the shop.", t0, t0, "r-fixes"))
    cases = [hub.ins("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,first_step,opened_in) "
                     "VALUES(?,?,?,'vps with open_case','open',?,'vps',?,?)",
                     (made["duty"], key, f"{key} touches the shop", t0, t0, made["work"]))
             for key in ("cve/1/shop", "cve/2/shop")]
    hub.q("INSERT INTO duty_joins(duty_case,responsibility,ts) VALUES(?,?,?)", (cases[0], made["joiner"], t0))
    hub.q("INSERT INTO duty_history(responsibility,ts,by,kind,detail) VALUES(?,?,'vps','case_joined',?)",
          (made["joiner"], t0, f"R-{made['duty']}/C-{cases[0]}: cve/1/shop touches the shop"))
    return made


def helper_calls():
    """What a helper of this tree sends where a newer helper changes the shape, built by its own code: the status
    report of a worker and of the manager (lifecycle.Lifecycle.collect, with every name of lifecycle.FEATURES and the
    vault part of fleet.vault_status), the usage report of usage.py, in the shape a helper sends first, in the one it
    sends to a hub that said it takes each session's kinds and in the one for a hub that said it takes each session's
    models too, and the screen watch's reports (runtime gaps C1, fleet.screen_report). The machine's readings are
    stand-ins; the shapes are this tree's. A lane whose helper changes another call's shape adds that call here, built
    by its own code.
    `python3 test_release_turns.py --before <commit>` builds them in this tree and gives them to the test of the
    older release in the file that FLEET_NEWER_HELPER names."""
    if os.environ.get("FLEET_NEWER_HELPER"):
        with open(os.environ["FLEET_NEWER_HELPER"], encoding="utf-8") as f:
            return json.load(f)

    def machine(argv, **_):
        """A Linux machine with ssh, a security update waiting, and Claude Code and Codex signed in."""
        words = " ".join(argv)
        for part, out in (("rev-parse HEAD", "c" * 40), ("uname -r", "6.8.0-45-generic"),
                          ("is-enabled unattended-upgrades", "enabled"), ("upgrade", "Inst libc6 [noble-security]"),
                          ("is-active", "active"), ("claude --version", "2.1.311 (Claude Code)"),
                          ("codex --version", "codex-cli 0.163.0"), ("auth status", '{"loggedIn": true}'),
                          ("login status", "Logged in using ChatGPT"),
                          ("claude --help", "--model <model> An alias ('sonnet' or 'opus') or a full name. "
                                            "--effort <level> Effort level (low, medium, high, max)")):
            if part in words:
                return 0, out + "\n", ""
        return 1, "", ""

    # a broker's own status answer: its program is root's copy, which no release reaches
    broker = {"callers": True, "creates": True, "captures": True, "requests": True, "deposits": True,
              "withdrawals": True, "places": True, "place_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + "A" * 43,
              "recipient": "age1" + "q" * 58, "source": "b" * 64}
    with patch.object(fleet, "broker_status", return_value=broker), \
            patch.object(fleet, "vault_mode", return_value="broker"), \
            patch.object(fleet, "vault_readable", return_value=[]):
        vault = fleet.vault_status("vps")
    home = os.path.realpath(tempfile.mkdtemp(prefix="fleet-newer-helper-"))
    try:
        def status(agent, role):
            conf = {"role": role, "runtime": "claude", "model": "claude-sonnet-5-5", "effort": "high",
                    "can": ["shell", "browser"], "screen_command": sys.executable,
                    "screen": {"model": "gpt-6.1-sol", "effort": "medium"}}
            switch = {"other_runtime_windows": ["owner-chat"], "owner_chat_bound": True}
            if role == "manager":
                switch.update(manager_bound=True, manager_handover={"codex": [7]})
            life = lifecycle.Lifecycle(KIT, agent, conf, None, lambda: False, run=machine, platform_name="linux",
                                       home=home, vault=lambda: vault, models=lambda exe: (None, "no model list here"),
                                       legacy=lambda: ["T-3"], switch=lambda: switch,
                                       which=lambda name: "/usr/local/bin/" + name)
            return dict(life.collect(), reading_age=0.25)

        # the usage report: one Claude session of two calls, and the account's cached limits
        kit, session = os.path.join(home, "fleet-pilot"), "5d1e6c2a-7b3f-4e8a-9c0d-1f2e3a4b5c6d"
        root = os.path.join(home, ".claude", "projects", re.sub(r"[^A-Za-z0-9-]", "-", kit))
        os.makedirs(root)
        with open(os.path.join(root, session + ".jsonl"), "w", encoding="utf-8") as f:
            for n, read, write in ((1, 0, 1000), (2, 1000, 30)):
                f.write(json.dumps({"type": "assistant", "cwd": kit, "sessionId": session, "isSidechain": False,
                                    "timestamp": f"2026-10-27T10:0{n}:00Z",
                                    "message": {"id": f"msg_{n}", "model": "claude-sonnet-5-5",
                                                "usage": {"input_tokens": 10, "output_tokens": 5,
                                                          "cache_read_input_tokens": read,
                                                          "cache_creation_input_tokens": write}}}) + "\n")
        account = "8a3f2c1e-1111-4222-8333-944455556666"
        with open(os.path.join(home, ".claude.json"), "w", encoding="utf-8") as f:
            json.dump({"oauthAccount": {"accountUuid": account, "organizationUuid": "org-1",
                                        "emailAddress": "pilot@example.com",
                                        "userRateLimitTier": "default_claude_max_20x"},
                       "cachedUsageUtilization": {"accountUuid": account, "fetchedAtMs": time.time() * 1000,
                                                  "utilization": {"limits": [
                                                      {"group": "session", "kind": "session", "percent": 12,
                                                       "resets_at": "2026-10-27T15:00:00Z"},
                                                      {"group": "weekly", "kind": "weekly", "percent": 40,
                                                       "scope": {"model": {"display_name": "Opus"}},
                                                       "resets_at": "2026-10-30T14:00:00Z"}]}}}, f)
        report = {"tokens": usage.transcript_tokens("claude", kit, home),
                  "limits": usage.claude_cache(home, "pilot@example.com")}
        # runtime gaps C1: the screen watch's reports (fleet.screen_report), of a task window and of the manager's
        dialog = {"task": [fleet.screen_report("shown", 1, False), fleet.screen_report("shown", 1, True),
                           fleet.screen_report("limit", 1), fleet.screen_report("gone", 1),
                           fleet.screen_report("frozen", 1), fleet.screen_report("moving", 1)],
                  "manager": [fleet.screen_report("limit"), fleet.screen_report("closed")]}
        return {"status": {"vps": status("vps", "worker"), "manager": status("manager", "manager")},
                "usage": {"plain": usage.plain_sessions(report), "kinds": usage.kinds_sessions(report),
                          "models": report}, "dialog": dialog}
    finally:
        shutil.rmtree(home, ignore_errors=True)


class HubFixture(unittest.TestCase):
    """The in-process hub of test_ui_api.OwnerAPI, without its tests: `python3 -m unittest
    test_release_turns.RollbackReads` runs the rollback reads and nothing else."""
    setUp, tearDown = test_releases.OwnerAPI.setUp, test_releases.OwnerAPI.tearDown
    connect, request = test_releases.OwnerAPI.connect, test_releases.OwnerAPI.request


class RollbackReads(HubFixture):
    """The previous release reads every new value (plan P0): this release, on a database and a team.json that the
    later lanes wrote, starts, ticks and answers its reads without an error. An unknown role reads as the most limited
    role, an unknown check form as quiet, a new column and a new table as absent."""

    def setUp(self):
        super().setUp()
        hub.TEAM = json.loads(json.dumps(LATER_TEAM))
        made = later_data()
        self.assertEqual(hub.build_schema(), [])        # this release's own start on the newer database
        self.peer, self.boss, self.talk, self.task, self.rule = (made[k] for k in ("peer", "boss", "talk", "task",
                                                                                     "rule"))
        self.secret_answer, self.work = made["secret_answer"], made["work"]
        self.asking, self.saved = made["asking"], made["saved"]
        self.joiner = made["joiner"]

    def test_a_task_that_waits_on_the_owners_secret_keeps_its_wait(self):
        """secret_requests: a task waits on its open request, and on its saved secret until a delivery reaches its
        machine. A release that knew neither told its requester that the task had stalled, and started its lost
        session again at once."""
        for tid, path in ((self.asking, "waiting for the owner's answer to N-91"),
                          (self.saved, "waiting for N-92 to reach vps's machine")):
            t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
            self.assertEqual(hub.live_reason(t, None)[0], "need")
            hub.liveness(hub.now())
            self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (tid,))["live_path"], path)
        hub.secret_wakes()                                                  # its delivery is still on its way
        self.assertEqual(hub.q1("SELECT state FROM tasks WHERE id=?", (self.saved,))["state"], "input-required")

    def test_a_workers_secret_answer_that_its_chat_read_comes_no_more(self):
        """secret_requests: his answer to a worker's request is a chat event that its chat reads once. A release that
        gave it at each read, and kept it pending for a reply that nothing can send, left the chat deaf: its helper
        types no new line while one is not taken."""
        context = (hub.kv_get("db_id"), "owner-chat", "1")
        self.assertNotIn("Saved the login", hub.call_tool("vps", "read_messages", {}, context)[0])
        code, data = self.request("/events/vps?delivery=1&wait=0", source="127.0.0.3")
        self.assertEqual(code, 200, data)
        self.assertNotIn(self.secret_answer, [e["id"] for e in data["events"]])

    def tick(self):
        """One pass of the hub's timers. A sweep that raises is printed and skipped there, so each one is a failure
        here."""
        printed = []
        with patch.dict(hub.CFG, {"silence": 180, "question_wait": 120, "manager_silence": 120, "stop_after": 60,
                                  "offline_after": 90, "tick": 5, "hook_wait": 240}), \
                patch.object(hub.traceback, "print_exc", lambda *a, **k: printed.append(sys.exc_info())):
            hub.tick()
        self.assertEqual(printed, [], "a sweep raised on the newer data")

    def test_the_hub_ticks_and_answers_its_reads_on_the_newer_data(self):
        self.tick()
        for path in ("/ui/state", "/ui/people?db=test-generation", "/ui/conversations?db=test-generation",
                     "/ui/triggers?db=test-generation", f"/ui/triggers/{self.rule}?db=test-generation",
                     "/ui/releases?db=test-generation", "/ui/responsibilities?db=test-generation",
                     f"/ui/responsibilities/{self.joiner}?db=test-generation", "/ui/memory/vps?db=test-generation"):
            with self.subTest(path):
                code, data = self.request(path)
                self.assertEqual(code, 200, data)

    def test_an_unknown_role_reads_as_the_most_limited_role(self):
        _, data = self.request("/ui/people?db=test-generation")
        people = {p["name"]: p for p in data["people"]}
        self.assertEqual((people["Bruno"]["role"], people["Angela"]["role"]), ("peer", "manager"))   # kept as stored
        # A name that no release knows reads as the customer does, with the customer's daily limit: in a release
        # before the roles table (lane L1) and in one with it, where the table is the list of the names it knows.
        stranger, customer = people["Lucia"], people["Ana"]
        self.assertEqual(stranger["role"], "auditor")
        self.assertEqual((stranger["role_means"], stranger["daily"]), (customer["role_means"], customer["daily"]))
        self.assertIsNotNone(stranger["daily"])
        # The peer's window: a release before the conversations of lane L2 gives a role that is not one of the four
        # of before the customer's closed window. From lane L2 on, contacts.v2 (on in LATER_TEAM) runs a peer's
        # conversation with the agent's own tools, for a helper that holds such a conversation and for no other.
        context = (hub.kv_get("db_id"), "conversation", str(self.talk))
        if not hasattr(hub, "CONVERSATION_WORK_TOOLS"):
            start = hub.conversation_start("vps", self.talk)
            self.assertEqual(start["tools"], list(hub.PERSON_TOOLS["customer"]))
            self.assertIn(hub.PERSON_ROLES["customer"], start["prompt"])
            self.assertEqual(hub.conversation_tools("vps", context), hub.PERSON_TOOLS["customer"])
            return
        reach = patch.object(hub, "contact_reach", lambda agent, person=None: True)    # the fleet before DevOps D5
        reach.start()
        self.addCleanup(reach.stop)
        with self.assertRaises(hub.Refusal):
            hub.conversation_start("vps", self.talk)
        helper_reports("vps", hub.CONVERSATION_TASKS)
        start = hub.conversation_start("vps", self.talk)
        self.assertEqual((start["closed"], start["tools"]), (False, list(hub.CONVERSATION_WORK_TOOLS)))
        self.assertTrue(set(hub.CONVERSATION_WORK_TOOLS) <= set(hub.conversation_tools("vps", context)))

    def test_a_check_of_an_unknown_form_reads_as_quiet(self):
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(UNKNOWN_CHECK), self.rule))
        self.tick()                             # its due time came: no run opens, and only its next due time moves
        self.assertEqual(hub.q("SELECT * FROM trigger_runs WHERE trigger_id=?", (self.rule,)), [])
        self.assertGreater(hub.q1("SELECT next_due FROM triggers WHERE id=?", (self.rule,))["next_due"], hub.now())
        run = hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,state,created,retry_at) "
                      "VALUES(?,1,?,'waiting',?,?)", (self.rule, hub.now(), hub.now(), hub.now()))
        self.tick()                             # a run that a later release opened ends quiet, and goes to no helper
        row = hub.q1("SELECT state, reason FROM trigger_runs WHERE id=?", (run,))
        self.assertEqual((row["state"], row["reason"]), ("quiet", hub.NEWER_CHECK))
        self.assertEqual(hub.q("SELECT * FROM events WHERE kind='trigger_check'"), [])
        with self.assertRaises(hub.Refusal) as refused:
            hub.check_now(hub.trigger_row(self.rule), hub.now())
        self.assertIn("newer form", str(refused.exception))
        said = hub.t_see_triggers("vps", {})
        self.assertIn("a check of a newer form", said)
        self.assertIn("a check of a newer form", hub.t_see_triggers("vps", {"trigger_id": self.rule}))

    def test_a_result_of_an_unknown_form_reads_as_quiet_and_a_new_field_as_absent(self):
        spec = {"path": "checks/queue.py", "commit": "c" * 40, "sha256": "b" * 64, "args": {}, "timeout_seconds": 30,
                "condition": {"op": ">", "value": 0}, "repeat_minutes": None}
        hub.q("UPDATE triggers SET check_spec=? WHERE id=?", (json.dumps(spec), self.rule))
        token = "11111111-2222-4333-8444-555555555555"
        run = hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,state,created,token,sent) "
                      "VALUES(?,1,?,'sent',?,?,?)", (self.rule, hub.now(), hub.now(), token, hub.now()))
        code, answer = self.request(f"/helper/trigger/vps/{run}", {"token": token, "ok": True,
                                                                   "lines": ["T-81 new ticket"]}, source="127.0.0.3")
        self.assertEqual((code, answer["decision"]), (200, "quiet"), answer)
        self.assertEqual(hub.q1("SELECT reason FROM trigger_runs WHERE id=?", (run,))["reason"], hub.NEWER_CHECK)
        self.assertEqual(hub.q("SELECT * FROM tasks WHERE trigger_id=?", (self.rule,)), [])
        body = hub.check_body({"token": token, "ok": True, "value": 0, "summary": "none", "lines": []})
        self.assertEqual(body, {"token": token, "ok": True, "value": 0, "summary": "none"})
        body = hub.check_body({"token": token, "ok": False, "error": "exit", "detail": "1", "tail": "Traceback"})
        self.assertEqual({k: v for k, v in body.items() if k != "tail"},       # lane L4's release keeps the tail
                         {"token": token, "ok": False, "error": "exit", "detail": "1"})

    def test_the_hub_takes_the_screen_reports_of_a_helper_of_the_newer_release(self):
        """Runtime gaps C1: the attempt of the window and whether a question stood still read as absent where a release
        does not know them, and a kind it does not know is a 400, after which the helper tells a usage-limit menu as a
        question, as before (Helper.watch_screens); the manager's closed session needs no word there."""
        calls = helper_calls().get("dialog")
        self.assertTrue(calls, "this tree's helper sends screen reports")
        for agent, path, source in (("vps", f"/helper/dialog/vps/T-{self.work}", "127.0.0.3"),
                                    ("manager", "/helper/dialog/manager/manager", "127.0.0.2")):
            for body in calls["task" if agent == "vps" else "manager"]:
                with self.subTest(agent=agent, body=body):
                    code, answer = self.request(path, body, source=source)
                    self.assertIn(code, (200, 400) if body["kind"] in ("limit", "closed") else (200,), answer)
        self.tick()

    def test_the_hub_takes_the_calls_of_a_helper_of_the_newer_release(self):
        """A helper stays on the newer release when its hub rolls back, so the release before takes what it sends. A
        status report it refuses is refused whole, with the machine's vault broker and its deliveries: the 33rd
        helper feature would have done that on 27 October 2026 (L8, 2d47ffd)."""
        calls = helper_calls()
        for agent, report in calls["status"].items():
            source = LATER_TEAM["addresses"][LATER_TEAM["agents"][agent]["machine"]]
            code, answer = self.request(f"/helper/status/{agent}", report, source=source)
            self.assertEqual(code, 200, answer)
            kept = json.loads(hub.q1("SELECT data FROM machine_status WHERE agent=?", (agent,))["data"])
            self.assertEqual(sorted(kept["features"]), sorted(set(report["features"])))
        code, answer = self.request("/helper/usage/vps", calls["usage"]["plain"], source="127.0.0.3")
        self.assertEqual(code, 200, answer)
        if answer.get("session_kinds") is True:         # the kinds go only to a hub that said it takes them
            code, answer = self.request("/helper/usage/vps", calls["usage"]["kinds"], source="127.0.0.3")
            self.assertEqual(code, 200, answer)
        if answer.get("session_models") is True:        # and the models to one that said it takes those too
            code, answer = self.request("/helper/usage/vps", calls["usage"]["models"], source="127.0.0.3")
            self.assertEqual(code, 200, answer)


# ---- the feature-flag convention (COORDINATION.md, "Autonomous teams")

# server.py's own report (server_status), not a helper's
SERVER_FEATURES = {"job_heartbeat", "server_names", "rename_key"}


def helper_reports(agent, *features, **data):
    """The status report of the agent's helper, as the hub keeps it, with these helper features: a test of a new
    helper behaviour runs once with its flag and once without it. A name that lifecycle.FEATURES does not list fails at
    once, because no helper would report it."""
    unknown = sorted(set(features) - set(lifecycle.FEATURES))
    if unknown:
        raise AssertionError(f"{unknown} not in lifecycle.FEATURES: no helper reports them")
    hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) ON CONFLICT(agent) DO UPDATE SET "
          "data=excluded.data, reported=excluded.reported", (agent, json.dumps(dict(data, features=list(features))),
                                                             hub.now()))


class FeatureFlags(unittest.TestCase):
    def test_every_helper_feature_the_hub_asks_for_is_one_a_helper_reports(self):
        """A flag that the hub reads and lifecycle.FEATURES does not list is a behaviour that never runs."""
        with open(os.path.join(KIT, "hub.py"), encoding="utf-8") as f:
            source = f.read()
        found = re.findall(r'(?:"([a-z_]+)"|\b([A-Z][A-Z_]+)) (?:not )?in (?:(?! in |\band\b|\bor\b)[^\n])*?'
                           r'(?:helper_features\(|\bfeatures\b)', source)
        names = {name for name, _ in found if name} | {getattr(hub, const) for _, const in found if const}
        self.assertGreater(len(names), 10, "the scan found too few: its pattern no longer matches the hub")
        self.assertEqual(sorted(names - set(lifecycle.FEATURES) - SERVER_FEATURES), [])

    def test_the_test_helper_refuses_a_flag_that_no_helper_reports(self):
        with self.assertRaises(AssertionError):
            helper_reports("vps", "no_such_feature")


def load_tests(loader, _tests, _pattern):
    """Only the tests of this file: the fixture it borrows from test_releases.py carries its own."""
    suite = unittest.TestSuite()
    for cls in (SessionSurvivesRestart, Turns, HelperUpdate, RollbackReads, FeatureFlags):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


def rollback_read(commit):
    """The rollback read against the release of `commit` (COORDINATION.md, "Readiness"): RollbackReads of that
    commit's hub, in a copy of its tree, with this file and with the calls of this tree's helper (helper_calls).
    Returns the exit status of the run."""
    with tempfile.TemporaryDirectory(prefix="fleet-rollback-") as tmp:
        tree = os.path.join(tmp, "tree")
        os.mkdir(tree)
        archive = subprocess.run(["git", "-C", KIT, "archive", commit], capture_output=True)
        if archive.returncode != 0:
            print(archive.stderr.decode(errors="replace").strip(), file=sys.stderr)
            return 2
        subprocess.run(["tar", "-x", "-C", tree], input=archive.stdout, check=True)
        shutil.copy(os.path.join(KIT, "test_release_turns.py"), tree)
        calls = os.path.join(tmp, "newer-helper.json")
        with open(calls, "w", encoding="utf-8") as f:
            json.dump(helper_calls(), f)
        print(f"RollbackReads of {commit}, with the helper calls of {KIT}", flush=True)
        return subprocess.run([sys.executable, "-m", "unittest", "test_release_turns.RollbackReads"], cwd=tree,
                              env=dict(os.environ, FLEET_NEWER_HELPER=calls)).returncode


if __name__ == "__main__":
    if sys.argv[1:2] == ["--before"] and len(sys.argv) == 3:
        sys.exit(rollback_read(sys.argv[2]))
    unittest.main()

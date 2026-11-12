"""Deterministic hub checks for thread records, pause and stop, usage-limit waits and live paths. No AI calls."""
import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import hub
from test_ui_api import own_attachments

SESSION = "0b7d5a8e-3c1f-4e2a-9d6b-1f2e3d4c5b6a"
SECRET = "Zq7Lm2Xc9Vb4Nn8K"


class Runtime(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fleet-runtime-test-")
        hub.DB = sqlite3.connect(self.tmp.name + "/test.db", check_same_thread=False)
        hub.DB.row_factory = sqlite3.Row
        hub.DB.executescript(hub.SCHEMA)
        hub.migrate()
        # This team pins no agent to an address on purpose: these checks drive the helper routes of studio and vps
        # from this one process, so each would need an address of its own. A hub that tells no agent apart by
        # address takes the name as given (hub.address_checked); the manager's own check below pins its machine
        # itself, because that is what it is about.
        hub.TEAM = {"addresses": {"owner": "127.0.0.1"},
                    "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                               "studio": {"role": "worker", "runtime": "claude", "machine": "mac-studio",
                                          "can": ["shell", "browser"]},
                               "vps": {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}}}
        hub.CFG.update(silence=180, question_wait=120, manager_silence=120, stop_after=60, offline_after=90,
                       ask_wait=1, ask_max=1, hook_wait=2, job_wait=1, tick=5)
        own_attachments(self, self.tmp.name + "/attachments")     # hub.tick() sweeps it (resilience review, item 12)
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

    # ---- helpers
    def call(self, method, path, body=None, client="deterministic-test"):
        headers = {"Content-Type": "application/json"}
        if client:
            headers["X-Fleet-Client"] = client
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers=headers, method=method)
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with op.open(req, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as response:
            with response:
                return response.code, json.load(response)

    def control(self, tid, action, request_id=None, **extra):
        return self.call("POST", f"/ui/tasks/{tid}/control",
                         dict(request_id=request_id or str(uuid.uuid4()), db="gen1", action=action, **extra))

    def settle(self, oid, finding, note="checked the outbox"):
        return self.call("POST", f"/ui/outcomes/{oid}", dict(request_id=str(uuid.uuid4()), db="gen1", finding=finding, note=note))

    def task(self, owner="studio", state="working"):
        text = hub.t_create_task("manager", {"owner": owner, "title": "Send the note once", "done_when": "outbox has it"})
        tid = int(text.split()[1][2:].rstrip("."))
        hub.q("UPDATE tasks SET state=?, started=? WHERE id=?", (state, hub.now() - 100 if state != "submitted" else None, tid))
        return tid

    def records(self, tid, records, attempt=1, session=SESSION, agent="studio", generation="gen1"):
        return self.call("POST", f"/helper/events/{agent}", dict(generation=generation, task=f"T-{tid}", attempt=attempt,
                                                                 session=session, events=records), client=None)

    def tool(self, agent, name, tid, **args):
        attempt = hub.q1("SELECT attempt FROM tasks WHERE id=?", (tid,))["attempt"]
        return hub.call_tool(agent, name, dict(args, task_id=f"T-{tid}"), context=("gen1", f"T-{tid}", str(attempt)))

    def said(self, agent, kind="say"):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent=? AND kind=? ORDER BY id", (agent, kind))]

    def delivered(self, agent):
        req = urllib.request.Request(self.base + f"/events/{agent}?delivery=1&after=0&wait=0")
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as response:
            return json.load(response)["events"]

    def alive(self, agent, *windows, seen=0):
        hub.know(agent)
        hub.q("UPDATE agents SET last_seen=?, alive=?, alive_ts=? WHERE name=?",
              (hub.now() - seen, ",".join(windows), hub.now() - seen, agent))

    # ---- 1. thread records
    def test_records_are_stored_once_masked_capped_and_read_by_cursor(self):
        salt = "ab12"
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
                ("pilot", salt, hashlib.sha256((salt + SECRET).encode()).hexdigest(), len(SECRET), ""))
        tid = self.task()
        batch = [{"seq": 1, "ts": 1791619200.0, "type": "session", "runtime": "claude", "session_id": SESSION},
                 {"seq": 2, "ts": None, "type": "agent_message", "text": f"the key is {SECRET}.\nnext line"},
                 {"seq": 3, "ts": None, "type": "tool_call", "tool_call_id": "toolu_1", "title": "Bash:\x1b[31m ls",
                  "kind": "execute", "status": "in_progress", "server": None},
                 {"seq": 4, "ts": None, "type": "tool_call_update", "tool_call_id": "toolu_1", "status": "completed",
                  "interrupted": False, "output": "a\nb"},
                 {"seq": 5, "ts": None, "type": "nonsense"}]
        code, body = self.records(tid, batch)
        self.assertEqual((code, body["stored"], body["last_seq"]), (200, 4, 5))
        self.assertEqual(self.records(tid, batch)[1]["stored"], 0)       # a repeat is stored once
        self.assertEqual(self.records(tid, [])[1]["last_seq"], 4)        # where a restarted helper continues
        code, page = self.call("GET", f"/ui/tasks/{tid}/events?db=gen1")
        self.assertEqual(code, 200)
        self.assertEqual([e["type"] for e in page["events"]], ["session", "agent_message", "tool_call", "tool_call_update"])
        self.assertEqual(page["events"][1]["text"], "the key is [Registered login removed]\nnext line")   # and its dot
        self.assertEqual(page["events"][2]["title"], "Bash: [31m ls")
        self.assertFalse(page["more"])
        code, rest = self.call("GET", f"/ui/tasks/{tid}/events?db=gen1&after={page['next']}")
        self.assertEqual(rest["events"], [])
        code, first = self.call("GET", f"/ui/tasks/{tid}/events?db=gen1&limit=2")
        self.assertEqual((len(first["events"]), first["more"]), (2, True))
        self.assertEqual(self.call("GET", f"/ui/tasks/{tid}/events?db=old")[0], 409)
        self.assertEqual(self.call("GET", f"/ui/tasks/{tid}/events?db=gen1&limit=0")[0], 400)
        self.assertEqual(self.call("GET", "/ui/tasks/99/events?db=gen1")[0], 404)
        self.assertEqual(self.records(tid, batch, generation="old")[0], 409)
        self.assertEqual(self.records(tid, batch, attempt=2)[0], 409)
        self.assertEqual(self.records(tid, batch, agent="vps")[0], 409)
        self.assertEqual(self.records(tid, batch, session="not-a-uuid")[0], 400)
        self.assertEqual(self.records(tid, [batch[1]] * 101)[0], 400)
        self.assertEqual(hub.leak_scan(), [])
        # AUTONOMY.md P6: every record is kept, however long the attempt; the cap of 5,000 and its marker are gone
        # (test_history.LongTask stores 5,200)
        more = [{"seq": n, "ts": None, "type": "agent_message", "text": str(n)} for n in range(6, 10)]
        code, body = self.records(tid, more)
        self.assertEqual((body["stored"], body["last_seq"]), (4, 9))
        kinds = [r["type"] for r in hub.q("SELECT type FROM thread_events WHERE task=? ORDER BY id", (tid,))]
        self.assertEqual(kinds.count("truncated"), 0)

    def test_each_attempt_keeps_its_turn_state_from_every_record(self):
        """Plan C1: turn ends, open calls and the last words are facts of the attempt, kept at intake, and each record
        counts once."""
        tid = self.task()
        call = lambda seq, cid, title: {"seq": seq, "type": "tool_call", "tool_call_id": cid, "title": title,
                                        "kind": "execute", "status": "in_progress"}
        batch = [{"seq": 1, "type": "user_message", "text": "Go."}, call(2, "b1", "Bash: npm run build"),
                 {"seq": 3, "type": "tool_call_update", "tool_call_id": "b1", "status": "in_progress", "background": True,
                  "interrupted": False, "output": "Command running in background with ID: x."},
                 call(4, "f1", "Bash: ls"), {"seq": 5, "type": "tool_call_update", "tool_call_id": "f1", "status": "completed"},
                 {"seq": 6, "type": "agent_message", "text": f"The build runs; the key is {SECRET}."},
                 {"seq": 7, "type": "result", "stop_reason": "end_turn"}]
        salt = "ab12"
        hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,?)",
                ("pilot", salt, hashlib.sha256((salt + SECRET).encode()).hexdigest(), len(SECRET), ""))
        self.assertEqual(self.records(tid, batch)[0], 200)
        self.records(tid, batch)                                            # a repeat counts nothing twice
        state = hub.turn_state(tid, 1)
        self.assertEqual((state["turns"], state["running"], state["how"]), (1, False, "end_turn"))
        self.assertEqual(list(state["calls"]), ["b1"])
        self.assertEqual(state["calls"]["b1"][0::2], ["Bash: npm run build", True])
        self.assertEqual(state["said"], "The build runs; the key is [Registered login removed]")
        self.assertEqual(hub.open_call(tid, 1)[0], "Bash: npm run build")    # the background build is still open
        self.records(tid, [{"seq": 8, "type": "user_message", "text": "Next."},
                           {"seq": 9, "type": "tool_call_update", "tool_call_id": "b1", "status": "completed"},
                           {"seq": 10, "type": "result", "stop_reason": "end_turn"}])
        state = hub.turn_state(tid, 1)
        self.assertEqual((state["turns"], state["seq"], state["calls"]), (2, 10, {}))
        self.assertIsNone(hub.open_call(tid, 1))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM thread_events WHERE task=? AND type='result'", (tid,))["n"], 2)
        # a record of a subagent neither starts nor ends a turn of the main session
        self.records(tid, [{"seq": 11, "type": "result", "stop_reason": "end_turn", "parent": "toolu_9"},
                           {"seq": 12, "type": "agent_message", "text": "inside", "parent": "toolu_9"}])
        self.assertEqual((hub.turn_state(tid, 1)["turns"], hub.turn_state(tid, 1)["running"]), (2, False))
        self.assertEqual(hub.leak_scan(), [])

    def test_the_manager_s_limit_report_starts_no_episode_the_hub_already_held(self):
        """Plan C1: the helper reads the manager's whole transcript again after a restart, so it may report a limit
        whose episode the hub held and ended already; the reset names the episode, and the report starts nothing."""
        reset = hub.now() + 3600
        hub.q("INSERT INTO agent_limits(agent,since,until,reset_known,ended) VALUES('manager',?,?,1,?)",
              (hub.now() - 100, reset, hub.now() - 10))
        code, body = self.call("POST", "/helper/limit/manager", {"resets_at": reset, "runtime": "claude"}, client=None)
        self.assertEqual((code, body["until"]), (200, None))
        code, body = self.call("POST", "/helper/limit/manager", {"resets_at": reset + 60, "runtime": "claude"}, client=None)
        self.assertEqual((code, body["until"]), (200, reset + 60))           # a new reset is a new episode

    def test_records_count_as_activity(self):
        tid = self.task()
        hub.q("UPDATE tasks SET nudge_level=2, last_activity=0 WHERE id=?", (tid,))
        self.records(tid, [{"seq": 1, "type": "agent_message", "text": "working"}])
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertEqual(t["nudge_level"], 0)                   # plan C9: a new turn clears the Stalled mark
        self.assertGreater(t["last_activity"], hub.now() - 5)

    # ---- 2. pause and stop
    def test_pause_finds_unknown_outcomes_and_resume_needs_a_check(self):
        tid = self.task()
        self.records(tid, [
            {"seq": 1, "type": "tool_call", "tool_call_id": "send", "title": "Bash: curl outbox", "kind": "execute", "status": "in_progress"},
            {"seq": 2, "type": "tool_call", "tool_call_id": "look", "title": "Read: a.txt", "kind": "read", "status": "in_progress"},
            {"seq": 3, "type": "tool_call", "tool_call_id": "note", "title": "fleet: report_progress", "kind": "other",
             "status": "in_progress", "server": "fleet"},
            {"seq": 4, "type": "tool_call", "tool_call_id": "done", "title": "Bash: ls", "kind": "execute", "status": "in_progress"},
            {"seq": 5, "type": "tool_call_update", "tool_call_id": "done", "status": "completed"},
            {"seq": 6, "type": "tool_call", "tool_call_id": "edit", "title": "Edit: out.txt", "kind": "edit", "status": "in_progress"}])
        first = str(uuid.uuid4())
        code, body = self.control(tid, "pause", first)
        self.assertEqual((code, body["hold"]["state"], body["changed"], body["replayed"]), (200, "requested", True, False))
        hold = body["hold"]["id"]
        self.assertEqual(self.control(tid, "pause", first)[1]["replayed"], True)
        self.assertEqual(self.control(tid, "stop", first)[0], 409)          # one UUID, one command
        self.assertEqual(self.control(tid, "pause")[1]["changed"], False)    # already paused
        self.assertTrue(any("The owner paused" in t for t in self.said("manager")))
        self.assertTrue(self.tool("studio", "report_progress", tid, note="x")[1])
        self.assertIn("HELD", self.tool("studio", "list_my_tasks", tid)[0])
        self.assertFalse(self.tool("studio", "read_messages", tid)[1])
        hub.emit("studio", "say", "[hub] a message for the held task", task=tid)
        kinds = [e["kind"] for e in self.delivered("studio")]
        self.assertIn("control", kinds)
        self.assertNotIn("say", kinds)                                     # nothing is typed into a held session
        self.records(tid, [{"seq": 7, "type": "tool_call_update", "tool_call_id": "edit", "status": "failed"}])
        self.assertEqual(self.call("POST", "/helper/control/studio", {"hold": hold, "confirmed": True,
            "flushed": [{"session": SESSION, "last_seq": 9}]}, client=None)[0], 409)      # records first
        code, body = self.call("POST", "/helper/control/studio", {"hold": hold, "confirmed": True, "detail": "idle",
            "flushed": [{"session": SESSION, "last_seq": 7}]}, client=None)
        self.assertEqual((code, body["state"]), (200, "stopped"))
        self.assertNotIn("control", [e["kind"] for e in self.delivered("studio")])
        unknown = {o["tool_call_id"]: o for o in hub.q("SELECT * FROM outcomes WHERE task=?", (tid,))}
        self.assertEqual(set(unknown), {"send", "edit"})
        code, body = self.control(tid, "resume")
        self.assertEqual(code, 409)
        self.assertIn("unknown outcomes", body["error"])
        self.assertEqual(self.settle(unknown["send"]["id"], "not_done")[0], 200)
        self.assertEqual(self.settle(unknown["send"]["id"], "done")[0], 409)            # settled once
        self.assertEqual(self.control(tid, "resume")[0], 409)                          # one is still unknown
        code, body = self.control(tid, "resume_check")
        self.assertEqual((code, body["resumed_with"], body["hold"]["state"]), (200, "new session", "released"))
        task = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertEqual((task["attempt"], task["restarts"]), (2, 0))
        start = self.said("studio", "task")[-1]
        self.assertIn("resolve_outcome", start)
        self.assertIn("Bash: curl outbox: not done", start)
        text, err = self.tool("studio", "deliver_result", tid, outcome="completed", what_was_done="sent",
                              where_output_is="outbox", how_checked="count")
        self.assertTrue(err and "resolve_outcome" in text)
        text, err = self.tool("studio", "resolve_outcome", tid, outcome_id=f"O-{unknown['edit']['id']}", finding="done",
                              evidence="the file has the line")
        self.assertFalse(err)
        self.assertIn("No unknown outcomes", text)
        self.assertFalse(self.tool("studio", "deliver_result", tid, outcome="completed", what_was_done="sent",
                                   where_output_is="outbox", how_checked="count")[1])
        self.assertTrue(any("resumed T-" in t for t in self.said("manager")))
        self.assertEqual(hub.leak_scan(), [])

    def test_resume_types_into_a_live_paused_session(self):
        tid = self.task()
        hold = self.control(tid, "pause")[1]["hold"]["id"]
        self.alive("studio", f"T-{tid}")
        self.call("POST", "/helper/control/studio", {"hold": hold, "confirmed": True, "flushed": []}, client=None)
        code, body = self.control(tid, "resume")
        self.assertEqual((code, body["resumed_with"]), (200, "message to its session"))
        self.assertEqual(hub.q1("SELECT attempt FROM tasks WHERE id=?", (tid,))["attempt"], 1)
        self.assertIn(f"T-{tid} is resumed by the owner", self.said("studio")[-1])
        self.assertIn("say", [e["kind"] for e in self.delivered("studio")])
        self.assertEqual(self.control(tid, "resume")[0], 409)                          # nothing is held now

    def test_a_background_command_is_the_unknown_outcome_and_its_wait_is_not(self):
        tid = self.task(owner="vps")
        self.records(tid, [
            {"seq": 1, "type": "tool_call", "tool_call_id": "c1", "title": "exec: start", "kind": "execute", "status": "in_progress"},
            {"seq": 2, "type": "tool_call_update", "tool_call_id": "c1", "status": "completed"},
            {"seq": 3, "type": "tool_call", "tool_call_id": "proc-94316", "title": "Shell (background): sleep 90 && curl",
             "kind": "execute", "status": "in_progress"},
            {"seq": 4, "type": "tool_call", "tool_call_id": "c2", "title": "Wait: background session 94316", "kind": "read",
             "status": "in_progress"}], agent="vps")
        hold = self.control(tid, "pause")[1]["hold"]["id"]
        self.records(tid, [{"seq": 5, "type": "tool_call_update", "tool_call_id": "c2", "status": "completed", "interrupted": True},
                           {"seq": 6, "type": "result", "stop_reason": "cancelled"}], agent="vps")
        self.call("POST", "/helper/control/vps", {"hold": hold, "confirmed": True, "ran": True,
                                                  "flushed": [{"session": SESSION, "last_seq": 6}]}, client=None)
        rows = hub.q("SELECT tool_call_id, title, state FROM outcomes WHERE task=?", (tid,))
        self.assertEqual([tuple(r) for r in rows], [("proc-94316", "Shell (background): sleep 90 && curl", "unknown")])

    def test_ended_processes_that_no_open_call_explains_are_one_unknown_outcome(self):
        explained, bare = self.task(owner="vps"), self.task()
        self.records(explained, [{"seq": 1, "type": "tool_call", "tool_call_id": "proc-94316", "kind": "execute",
                                  "title": "Shell (background): sleep 90 && curl", "status": "in_progress"}], agent="vps")
        # Claude Code's Bash with run_in_background: the call completes at once, its command still runs
        self.records(bare, [{"seq": 1, "type": "tool_call", "tool_call_id": "toolu_bg", "title": "Bash: sleep 90 && curl",
                             "kind": "execute", "status": "in_progress"},
                            {"seq": 2, "type": "tool_call_update", "tool_call_id": "toolu_bg", "status": "completed"}])
        holds = {}
        for tid, agent in ((explained, "vps"), (bare, "studio")):
            holds[tid] = self.control(tid, "pause")[1]["hold"]["id"]
            for wrong in (-1, "2", True):
                self.assertEqual(self.call("POST", f"/helper/control/{agent}", {"hold": holds[tid], "confirmed": True,
                                                                               "ended": wrong}, client=None)[0], 400)
            self.call("POST", f"/helper/control/{agent}", {"hold": holds[tid], "confirmed": True, "ran": True, "ended": 2,
                                                          "flushed": []}, client=None)

        def rows(tid):
            return [tuple(r) for r in hub.q("SELECT tool_call_id, title, kind, state FROM outcomes WHERE task=? ORDER BY id", (tid,))]
        title = "The stop ended {} running command process(es); check what they did"
        self.assertEqual(rows(explained), [("proc-94316", "Shell (background): sleep 90 && curl", "execute", "unknown")])
        self.assertEqual(rows(bare), [(f"ended-{holds[bare]}", title.format(2), "other", "unknown")])
        self.assertEqual(self.control(bare, "resume")[0], 409)                         # Resume needs a check
        # A later hold of the same attempt: the call that the first hold recorded explains no newly ended process.
        self.assertEqual(self.settle(hub.q1("SELECT id FROM outcomes WHERE task=?", (explained,))["id"], "not_done")[0], 200)
        self.alive("vps", f"T-{explained}")
        self.assertEqual(self.control(explained, "resume")[1]["resumed_with"], "message to its session")
        again = self.control(explained, "pause")[1]["hold"]["id"]
        self.call("POST", "/helper/control/vps", {"hold": again, "confirmed": True, "ran": True, "ended": 1, "flushed": []},
                  client=None)
        self.assertEqual(rows(explained)[1:], [(f"ended-{again}", title.format(1), "other", "unknown")])
        self.assertEqual(self.control(explained, "resume")[0], 409)

    def test_file_change_and_subagent_fields_are_kept_by_the_allowlist(self):
        tid = self.task()
        long_id = "toolu_A/" + "n" * 150 + "/x1"
        self.records(tid, [
            {"seq": 1, "type": "tool_call", "tool_call_id": "toolu_A", "title": "Agent: check", "kind": "other",
             "status": "in_progress", "subagent": {"name": "general-purpose", "secret": "x"}},
            {"seq": 2, "type": "tool_call", "tool_call_id": long_id, "title": "Edit: a.txt", "kind": "edit",
             "status": "completed", "parent": "toolu_A", "locations": [{"path": "a.txt"}] * 30,
             "changes": [{"path": "a.txt", "action": "modify", "added": 2, "removed": True, "text": "secret body"},
                         {"path": "b.txt", "action": "rename"}] + [{"path": f"f{n}", "action": "add", "added": 1, "removed": 0}
                                                                  for n in range(60)]},
            {"seq": 3, "type": "tool_call", "tool_call_id": "r1", "title": "Read: a", "kind": "read", "status": "completed",
             "changes": [{"path": "a.txt", "action": "modify", "added": 1, "removed": 0}]},
            {"seq": 4, "type": "agent_message", "text": "child says", "parent": "toolu_A"}])
        events = {e["seq"]: e for e in self.call("GET", f"/ui/tasks/{tid}/events?db=gen1")[1]["events"]}
        self.assertEqual(events[1]["subagent"], {"name": "general-purpose"})
        self.assertEqual(events[2]["tool_call_id"], long_id)
        self.assertEqual((events[2]["parent"], len(events[2]["locations"]), len(events[2]["changes"])), ("toolu_A", 20, 50))
        self.assertEqual(events[2]["changes"][0], {"path": "a.txt", "action": "modify", "added": 2, "removed": None})
        self.assertNotIn("secret body", json.dumps(events))
        self.assertNotIn("changes", events[3])                 # only edit, delete and move calls carry changes
        self.assertEqual(events[4]["parent"], "toolu_A")
        features = self.call("GET", "/ui/state")[1]["ui_features"]
        self.assertTrue({"file_changes", "subagents"} <= set(features))

    def test_a_subagents_open_calls_take_part_in_unknown_outcomes(self):
        tid = self.task()
        self.records(tid, [
            {"seq": 1, "type": "tool_call", "tool_call_id": "toolu_A", "title": "Agent: deploy", "kind": "other",
             "status": "in_progress", "subagent": {"name": "general-purpose"}},
            {"seq": 2, "type": "tool_call", "tool_call_id": "toolu_A/x1", "title": "Bash: curl outbox", "kind": "execute",
             "status": "in_progress", "parent": "toolu_A"},
            {"seq": 3, "type": "tool_call", "tool_call_id": "toolu_A/r1", "title": "Read: notes", "kind": "read",
             "status": "in_progress", "parent": "toolu_A"}])
        hold = self.control(tid, "pause")[1]["hold"]["id"]
        self.call("POST", "/helper/control/studio", {"hold": hold, "confirmed": True, "flushed": [], "ran": True}, client=None)
        rows = [r["tool_call_id"] for r in hub.q("SELECT tool_call_id FROM outcomes WHERE task=? ORDER BY id", (tid,))]
        self.assertEqual(rows, ["toolu_A", "toolu_A/x1"])

    def test_a_session_that_ran_without_records_is_unknown_as_a_whole(self):
        quiet, idle = self.task(), self.task()
        for tid, ran in ((quiet, True), (idle, False)):
            hold = self.control(tid, "stop")[1]["hold"]["id"]
            self.call("POST", "/helper/control/studio", {"hold": hold, "confirmed": True, "flushed": [], "ran": ran}, client=None)
        rows = hub.q("SELECT task, tool_call_id, state FROM outcomes ORDER BY id")
        self.assertEqual([tuple(r) for r in rows], [(quiet, "attempt-1", "unknown")])
        self.assertEqual(self.control(quiet, "resume")[0], 409)
        self.assertEqual(self.control(idle, "resume")[0], 200)

    def test_stop_upgrades_a_pause_and_an_unconfirmed_stop_can_be_asked_again(self):
        tid = self.task()
        pause = self.control(tid, "pause")[1]["hold"]
        stop = self.control(tid, "stop")[1]["hold"]
        self.assertEqual((stop["id"], stop["kind"], stop["state"]), (pause["id"], "stop", "requested"))
        controls = [e for e in self.delivered("studio") if e["kind"] == "control"]
        self.assertEqual([e["extra"]["action"] for e in controls], ["stop"])           # the pause request is stale
        code, body = self.call("POST", "/helper/control/studio", {"hold": stop["id"], "confirmed": False,
            "detail": "still working", "flushed": []}, client=None)
        self.assertEqual(body["state"], "not_confirmed")
        self.assertEqual(self.control(tid, "stop")[1]["hold"]["state"], "requested")
        self.assertEqual(self.call("POST", "/helper/control/vps", {"hold": stop["id"], "confirmed": True}, client=None)[0], 404)

    def test_a_hold_answers_a_waiting_permission_prompt_and_refuses_new_ones(self):
        tid = self.task()
        hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created) VALUES(?,?,?,?,?,?)",
                (tid, "studio", "Bash", "make", "k", hub.now()))
        self.control(tid, "stop")
        self.assertEqual(hub.q1("SELECT decision, by FROM prompts WHERE task=?", (tid,))["decision"], "deny")
        code, body = self.call("POST", f"/hook/permission/studio/T-{tid}", {"tool_name": "Bash", "tool_input": {"command": "ls"},
                                                                            "generation": "gen1", "attempt": 1}, client=None)
        self.assertEqual(body["hookSpecificOutput"]["decision"]["behavior"], "deny")
        self.assertIn("stopped", body["hookSpecificOutput"]["decision"]["message"])

    def test_cancel_releases_the_hold_and_refusals_leave_no_record(self):
        tid = self.task()
        self.assertEqual(self.control(tid, "jump")[0], 400)
        self.assertEqual(self.call("POST", f"/ui/tasks/{tid}/control", dict(request_id="x", db="gen1", action="pause"))[0], 400)
        self.assertEqual(self.call("POST", f"/ui/tasks/{tid}/control", dict(request_id=str(uuid.uuid4()), db="old", action="pause"))[0], 409)
        self.assertEqual(self.call("POST", f"/ui/tasks/{tid}/control", dict(request_id=str(uuid.uuid4()), db="gen1", action="pause"), client="")[0], 400)
        self.assertEqual(self.control(99, "pause")[0], 404)
        self.assertEqual(self.control(tid, "pause", note=f"use {SECRET}")[0], 200)
        hub.t_cancel_task("manager", {"task_id": f"T-{tid}", "reason": "not needed"})
        self.assertEqual(hub.q1("SELECT state FROM holds WHERE task=?", (tid,))["state"], "released")
        self.assertEqual(self.control(tid, "pause")[0], 409)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM ui_controls")["n"], 1)

    # ---- 3. usage limits
    def test_a_usage_limit_holds_work_and_resumes_it_once(self):
        tid = self.task()
        self.alive("studio", f"T-{tid}")
        reset = hub.now() + 600
        limit = {"seq": 1, "type": "error", "code": "usage_limit", "message": "limit", "retryable": True, "resets_at": reset}
        self.records(tid, [limit])
        self.records(tid, [dict(limit, seq=2)])
        lim = hub.active_limit("studio")
        self.assertEqual((round(lim["until"]), lim["reset_known"]), (round(reset), 1))
        self.assertEqual(sum("reached its usage limit" in t for t in self.said("manager")), 1)
        state = self.call("GET", "/ui/state")[1]
        self.assertEqual(next(a for a in state["agents"] if a["name"] == "studio")["limit"]["until"], lim["until"])
        # The hub's own word about the limit is the one say that reaches a limited session: held until the reset it
        # would arrive stale, and it is what tells the session why it is about to go quiet. Nothing else passes.
        self.assertEqual([e["text"][:35] for e in self.delivered("studio") if e["kind"] == "say"],
                         ["[hub] You reached your usage limit."])
        hub.emit("studio", "say", "[hub] answer", task=tid)
        later = self.task()
        self.assertIn("usage limit", hub.t_create_task("manager", {"owner": "studio", "title": "x", "done_when": "y"}))
        kinds = [e["kind"] for e in self.delivered("studio")]
        self.assertNotIn("[hub] answer", [e["text"] for e in self.delivered("studio")])
        self.assertNotIn("task", kinds)
        hub.q("UPDATE tasks SET last_activity=0 WHERE id=?", (tid,))
        hub.tick()
        self.assertFalse(any("No activity" in t for t in self.said("studio")))      # no nudges while limited
        self.assertEqual(hub.q1("SELECT live_path FROM tasks WHERE id=?", (later,))["live_path"][:24], "waiting for studio's usa")
        hub.q("UPDATE agent_limits SET until=?", (hub.now() - 1,))
        hub.tick()
        self.assertIsNone(hub.active_limit("studio"))
        self.assertIn("[hub] answer", [e["text"] for e in self.delivered("studio")])   # held messages flow at the reset
        # plan C9: at the reset the hub reads the attempt at once: its idle session gets the resume message
        self.assertIn(f"Continue T-{tid}", self.said("studio")[-1])
        self.assertTrue(any("usage limit has reset" in t for t in self.said("manager")))
        before = len(self.said("studio"))
        hub.tick()
        self.assertEqual(len(self.said("studio")), before)                          # resumed one time only
        self.assertIn("task", [e["kind"] for e in self.delivered("studio")])

    # account_limits: a hold belongs to one agent, an allowance belongs to one account. studio and vps stand for the
    # live pair on one Codex account (vps and worker4): same provider account key, so one
    # allowance. The route and the runtime of each agent are its own; the account key is what groups them.
    def reading(self, agent, key, used, reset, labels=("codex / 7 days",), minutes=10080):
        hub.q("INSERT INTO agent_usage(name,data) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET data=excluded.data",
              (agent, json.dumps({"tokens": None, "limits": {
                  "collected_at": hub.now(), "source": "test", "plan": "pro", "account_key": key, "error": None,
                  "windows": [{"id": f"w{i}", "label": label, "used_percent": used, "resets_at": reset,
                               "window_minutes": minutes} for i, label in enumerate(labels)]}})))

    def shared(self, used=100, labels=("codex / 7 days",)):
        """studio and vps on one provider account, with a working task each and a live session each. Both read the
        same account, so both readings carry the same windows; the group takes the newest of them, as account_state
        does. Returns (the reset, studio's task, vps's task)."""
        later = hub.now() + 3600
        key = "openai:" + "a" * 32
        self.reading("studio", key, used, later, labels)
        self.reading("vps", key, 40, later, labels)
        mine, theirs = self.task(), self.task(owner="vps")
        self.alive("studio", f"T-{mine}")
        self.alive("vps", f"T-{theirs}")
        return later, mine, theirs

    def hit(self, tid, reset, agent="studio", seq=1):
        self.records(tid, [{"seq": seq, "type": "error", "code": "usage_limit", "resets_at": reset}], agent=agent)

    def test_a_limit_holds_every_agent_that_spends_the_same_allowance(self):
        """The defect the review measured (experiment S5): the advice layer already marked both agents limited and
        counted the shared account once, while the enforcement layer held only the agent whose session reported it.
        So create_task for the other was taken, its helper was handed the task, and the session started on a
        used-up account and failed on its first call -- which is when the hub first learned."""
        later, mine, theirs = self.shared()
        self.hit(mine, later)
        held = hub.active_limit("vps")
        self.assertEqual((round(held["until"]), held["reset_known"], held["route"], held["task"]),
                         (round(later), 1, "primary", None))
        self.assertEqual(hub.limit_source(held), "studio")                      # where it came from, on the row
        self.assertIsNone(hub.limit_source(hub.active_limit("studio")))          # the one that reported it
        # One message for the episode, and it names the other agent where the manager chooses who works.
        limits = [t for t in self.said("manager") if "reached its usage limit" in t]
        self.assertEqual(len(limits), 1)
        self.assertIn("vps spends the same provider allowance", limits[0])
        # vps's own live session is told, and the hub's own word reaches it although vps is held from this moment.
        self.assertTrue(any("A session of studio on the provider account you share" in e["text"]
                            for e in self.delivered("vps") if e["kind"] == "say"))
        # and every clock leaves the held agent alone, as it leaves the one that reported
        self.assertIn("is held until", hub.t_create_task("manager", {"owner": "vps", "title": "x", "done_when": "y"}))
        hub.q("UPDATE tasks SET last_activity=0 WHERE id=?", (theirs,))
        hub.tick()
        self.assertFalse(any("No activity" in t for t in self.said("vps")))
        self.assertIn("the account vps shares with studio",
                      hub.q1("SELECT live_path FROM tasks WHERE id=?", (theirs,))["live_path"])
        self.assertIn("YOUR ALLOWANCE is used up: a session of studio", hub.start_text("vps", theirs))

    def test_a_window_that_is_one_models_share_of_an_account_holds_nobody_else(self):
        """The trap. A usage window can be scoped to one model -- the live hub shows "7 days (Fable)" on one login
        -- and a reported limit carries nothing but a reset time, so the hub cannot say which window a session hit.
        Holding the other agents on such an account would let one model's limit take the fleet down."""
        later, mine, _ = self.shared(labels=("7 days (Fable)",))
        self.hit(mine, later)
        self.assertIsNotNone(hub.active_limit("studio"))
        self.assertIsNone(hub.active_limit("vps"))                              # another model, same account
        said = [t for t in self.said("manager") if "reached its usage limit" in t][0]
        self.assertIn("The hub holds no other agent for it: this account reports a window that is one model's "
                      "share of it (\"7 days (Fable)\")", said)

    def test_an_account_whose_windows_the_hub_cannot_read_as_its_own_holds_nobody_else(self):
        """The same rule for the shapes that are not a scope suffix: one window for each of several provider limit
        ids, and an account reading with no window at all. Reading this wrongly must cost a hold that does not
        spread, never one that spreads too far."""
        later, mine, _ = self.shared(labels=("gpt-5 / 7 days", "gpt-5-codex / 7 days"))
        self.hit(mine, later)
        self.assertIsNone(hub.active_limit("vps"))
        self.assertIn("a window for each of gpt-5, gpt-5-codex",
                      [t for t in self.said("manager") if "reached its usage limit" in t][0])
        hub.q("DELETE FROM agent_limits")
        # The account's NEWEST reading decides for every route on it (account_state), so an account with no window
        # is one where no reading of it has one.
        for agent in ("studio", "vps"):
            hub.q("UPDATE agent_usage SET data=? WHERE name=?",
                  (json.dumps({"tokens": None, "limits": {"collected_at": hub.now(), "source": "test", "plan": "pro",
                                                          "account_key": "openai:" + "a" * 32, "windows": [],
                                                          "error": "No account limits were reported."}}), agent))
        self.hit(mine, later, seq=2)
        self.assertIsNone(hub.active_limit("vps"))
        self.assertIn("names no allowance window",
                      [t for t in self.said("manager") if "reached its usage limit" in t][-1])

    def test_one_reset_ends_the_whole_episode_once_and_costs_no_restart(self):
        """A held agent that never reported a limit of its own resumes exactly once, as the one that reported does,
        and the manager reads one message for the episode and not one for each agent. The new session is not
        counted, so a reset never spends one of the three session restarts."""
        later, mine, theirs = self.shared()
        self.hit(mine, later)
        hub.q("UPDATE agents SET alive=NULL, alive_ts=NULL WHERE name='vps'")       # its session died while held
        hub.q("UPDATE tasks SET last_activity=0 WHERE id IN (?,?)", (mine, theirs))   # neither went on by itself
        hub.q("UPDATE agent_limits SET until=?", (hub.now() - 1,))                  # plan C9: no grace after a reset
        hub.tick()
        self.assertIsNone(hub.active_limit("vps"))
        self.assertIsNone(hub.active_limit("studio"))
        resets = [t for t in self.said("manager") if "has reset" in t]
        self.assertEqual(len(resets), 1)                                            # one episode, one message
        self.assertIn("the provider account that studio and vps share has reset", resets[0])
        self.assertIn(f"vps: T-{theirs} (new session)", resets[0])
        t = hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (theirs,))
        self.assertEqual((t["attempt"], t["restarts"]), (2, 0))                      # resumed, and no restart spent
        before = len(self.said("vps")), len(self.said("manager"))
        hub.tick()
        hub.tick()
        self.assertEqual((len(self.said("vps")), len(self.said("manager"))), before)  # resumed one time only

    def test_a_better_reset_time_moves_every_agent_of_the_episode(self):
        """The rows of one episode carry one reset, so a later and better one moves all of them -- whichever of the
        two the second report comes in on. Otherwise a held agent would wake before the allowance did."""
        later, mine, theirs = self.shared()
        self.hit(mine, None)                                                        # no reset time: one hour
        self.assertEqual(round(hub.active_limit("vps")["until"] - hub.now()), 3600)
        self.hit(mine, later + 7200, seq=2)
        for agent in ("studio", "vps"):
            lim = hub.active_limit(agent)
            self.assertEqual((round(lim["until"]), lim["reset_known"]), (round(later + 7200), 1))

    def test_work_that_continued_by_itself_after_a_reset_is_not_resumed(self):
        tid = self.task()
        self.alive("studio", f"T-{tid}")
        self.records(tid, [{"seq": 1, "type": "error", "code": "usage_limit", "resets_at": hub.now() + 60}])
        hub.q("UPDATE agent_limits SET until=?", (hub.now() - 1,))
        self.records(tid, [{"seq": 2, "type": "user_message", "text": "Go on."}])   # its turn runs again by itself
        hub.tick()
        hub.tick()
        self.assertFalse(any(f"Continue T-{tid}" in t for t in self.said("studio")))
        self.assertTrue(any("nothing was waiting" in t for t in self.said("manager")))

    def test_the_managers_own_limit_is_told_to_the_owner_and_holds_its_signals(self):
        hub.know("manager")
        hub.emit("manager", "say", "[owner] a goal that must wait")
        hub.TEAM["addresses"]["hub"] = "127.0.0.2"                                  # the manager's machine is elsewhere
        self.assertEqual(self.call("POST", "/helper/limit/manager", {"resets_at": hub.now() + 900}, client=None)[0], 403)
        hub.TEAM["addresses"]["hub"] = "127.0.0.1"                                  # now the call comes from the manager's machine
        code, body = self.call("POST", "/helper/limit/manager", {"resets_at": hub.now() + 900}, client=None)
        self.assertEqual(code, 200)
        self.assertEqual(self.call("POST", "/helper/limit/manager", {"resets_at": "soon"}, client=None)[0], 400)
        self.assertEqual(self.said("manager"), ["[owner] a goal that must wait"])    # no message to the limited manager
        self.assertEqual(self.delivered("manager"), [])
        hub.q("UPDATE events SET created=? WHERE agent='manager'", (hub.now() - 1000,))
        hub.tick()
        self.assertEqual(hub.kv_get("mgr_flag_kind"), "limited")
        self.assertIn("usage limit", hub.kv_get("mgr_flag"))
        self.assertIn(hub.owner_clock(hub.active_limit("manager")["until"]), hub.kv_get("mgr_flag"))   # his zone
        self.assertEqual(sum("usage limit" in t for t in self.said("owner", "notify")), 1)
        state = self.call("GET", "/ui/state")[1]
        self.assertIsNotNone(next(a for a in state["agents"] if a["name"] == "manager")["limit"])
        hub.q("UPDATE agent_limits SET until=?", (hub.now() - 1,))
        hub.tick()
        self.assertIsNone(hub.kv_get("mgr_flag"))                                   # no false "silent" alarm at the reset
        self.assertEqual([e["kind"] for e in self.delivered("manager")], ["say"])

    def test_limit_without_reset_waits_one_hour_and_a_past_reset_holds_nothing(self):
        tid = self.task(owner="vps")
        self.records(tid, [{"seq": 1, "type": "error", "code": "usage_limit", "resets_at": hub.now() - 5}], agent="vps")
        self.assertIsNone(hub.active_limit("vps"))
        self.records(tid, [{"seq": 2, "type": "error", "code": "usage_limit", "resets_at": None}], agent="vps")
        lim = hub.active_limit("vps")
        self.assertAlmostEqual(lim["until"] - lim["since"], 3600, delta=2)
        self.assertEqual(lim["reset_known"], 0)
        reset = hub.now() + 120
        self.records(tid, [{"seq": 3, "type": "error", "code": "usage_limit", "resets_at": reset}], agent="vps")
        self.assertEqual(round(hub.active_limit("vps")["until"]), round(reset))     # a known reset replaces the guess

    # ---- 4. live paths
    def test_a_task_with_an_offline_helper_is_reported_once(self):
        tid = self.task()
        self.alive("studio", seen=1000)
        # silence counts from the hub's own start at the earliest (plan C2): this hub has run for a day
        patcher = patch.object(hub, "STARTED", hub.now() - 86400)
        patcher.start()
        self.addCleanup(patcher.stop)
        hub.tick()
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertIsNone(t["live_path"])
        # in the owner's words: the agent as he names it, its silence, and no "helper" (T-37)
        self.assertRegex(t["stalled_reason"], r"^Studio has been silent since \d\d:\d\d$")
        hub.tick()
        said = self.said("manager")
        # plan C10: told at the label flip, once; the manager's notice of the machine names the task, so it gets no
        # notice of its own about it
        self.assertEqual(sum("has no live path" in t for t in said), 0)
        self.assertEqual(sum("studio's machine went offline" in t and f"T-{tid}" in t for t in said), 1)
        self.assertEqual(hub.q1("SELECT stall_told FROM tasks WHERE id=?", (tid,))["stall_told"], 1)
        self.alive("studio", f"T-{tid}")
        hub.tick()
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertEqual((t["live_path"], t["stalled_since"], t["stall_told"]), ("live session", None, 0))
        state = self.call("GET", "/ui/state")[1]
        self.assertEqual(next(x for x in state["tasks"] if x["id"] == tid)["live_path"], "live session")

    def test_a_vanished_session_restarts_but_a_waiting_question_does_not(self):
        lost = self.task()
        asking = self.task(state="input-required")
        hub.ins("INSERT INTO questions(task,asker,requester,text,asked) VALUES(?,?,?,?,?)",
                (asking, "studio", "manager", "Which label?", hub.now()))
        self.alive("studio", "T-999")
        hub.tick()
        self.assertIsNotNone(hub.q1("SELECT missing_since FROM tasks WHERE id=?", (lost,))["missing_since"])
        hub.q("UPDATE tasks SET missing_since=? WHERE id=?", (hub.now() - 40, lost))
        hub.tick()
        lost_t, asking_t = (hub.q1("SELECT * FROM tasks WHERE id=?", (i,)) for i in (lost, asking))
        self.assertEqual((lost_t["attempt"], lost_t["restarts"]), (2, 1))
        self.assertEqual(hub.q1("SELECT reason FROM attempts WHERE task=? AND attempt=2", (lost,))["reason"], "restart")
        self.assertEqual((asking_t["attempt"], asking_t["live_path"]), (1, "waiting for the answer to Q-1"))

    def lose_the_session(self, tid, lived):
        """The session of task `tid` has gone, and it had lived `lived` seconds when it went. One tick then decides.
        `missing_since` is the tick that first saw the session gone, which the hub writes itself; these rows put it
        40 seconds back, so the 30-second wait of liveness is over on this tick."""
        gone = hub.now() - 40
        hub.q("UPDATE tasks SET started=?, missing_since=? WHERE id=?", (gone - lived, gone, tid))
        hub.tick()
        return tuple(hub.q1("SELECT attempt, restarts FROM tasks WHERE id=?", (tid,)))

    def told_it_gave_up(self):
        return [t for t in self.said("manager") if "no running session" in t]

    def test_a_session_that_lived_long_is_restarted_and_spends_none_of_the_three(self):
        """The resilience review's S3b (20 October 2026): a session that lives 20 hours and is then lost, four times
        in a row, used the whole budget and got "no running session after 3 restarts" at 80 hours with no recovery.
        Three machine reboots over three days did the same, and one usage-limit episode could cost a restart (S4).
        Three is a crash-loop brake, so only a session that died young spends one of them."""
        tid = self.task()
        self.alive("studio", "T-999")               # its helper is online and lists no window of this task
        for n in range(4):
            self.assertEqual(self.lose_the_session(tid, 20 * 3600), (n + 2, 0))
        self.assertEqual([r["reason"] for r in hub.q("SELECT reason FROM attempts WHERE task=? ORDER BY attempt", (tid,))],
                         ["created"] + ["restart"] * 4)
        self.assertEqual(self.told_it_gave_up(), [])
        self.assertIn("not counted: it was not a crash loop", " ".join(r["what"] for r in hub.q("SELECT what FROM log")))

    def test_a_session_that_dies_young_three_times_is_stopped_and_reported_once(self):
        """The case that must not regress. A session that dies in seconds is a crash loop: three of those and the
        hub gives up, tells the requester once, and starts no session again -- for ever, however long it sits."""
        tid = self.task()
        self.alive("studio", "T-999")
        for n in range(hub.SESSION_RESTARTS):
            self.assertEqual(self.lose_the_session(tid, 20), (n + 2, n + 1))
        for _ in range(3):
            self.assertEqual(self.lose_the_session(tid, 20), (hub.SESSION_RESTARTS + 1, hub.SESSION_RESTARTS + 1))
        told, = self.told_it_gave_up()
        self.assertIn("This one was lost within 10 minutes of its own start", told)
        self.assertIn("studio's runtime may be signed out, or its session may be failing to start", told)

    def test_a_long_life_is_forgiven_once_and_not_for_ever(self):
        """The bound is not escaped by living long once: the session that replaces a long-lived one is lost young
        when it never comes up, so the budget takes that loss and three failed starts still stop the task."""
        tid = self.task()
        self.alive("studio", "T-999")
        self.assertEqual(self.lose_the_session(tid, 20 * 3600), (2, 0))
        for n in range(hub.SESSION_RESTARTS):
            self.assertEqual(self.lose_the_session(tid, 50), (n + 3, n + 1))
        self.assertEqual(self.lose_the_session(tid, 50), (hub.SESSION_RESTARTS + 2, hub.SESSION_RESTARTS + 1))
        self.assertEqual(len(self.told_it_gave_up()), 1)

    def test_the_stalled_mark_puts_a_task_on_the_owners_rung_until_a_new_attempt(self):
        """Plan C9: no silence clock. A task whose requester was told after two empty turn ends (nudge_level 2) is on
        the owner's stuck rung (tasks_stuck, version 1.35) until an event; a new attempt is one."""
        tid = self.task()
        hub.q("UPDATE tasks SET nudge_level=2, nudged_at=? WHERE id=?", (hub.now() - 3 * 3600, tid))
        hub.stuck_told(tid, hub.emit("manager", "say", f"[hub] T-{tid} ended two turns in a row.", task=tid))
        hub.kv_set("turn_ended:manager", hub.now() + 1)        # plan C10: the manager had a turn and did not read it
        line, = hub.tasks_stuck(hub.now())
        self.assertIn(f"T-{tid} (Send the note once, owner studio) ended two turns in a row with nothing waiting",
                      line[1])
        self.alive("studio", "T-999")
        self.assertEqual(self.lose_the_session(tid, 20 * 3600), (2, 0))
        self.assertEqual(hub.q1("SELECT nudge_level FROM tasks WHERE id=?", (tid,))["nudge_level"], 0)
        self.assertEqual(hub.tasks_stuck(hub.now()), [])

    def test_held_tasks_have_a_live_path_and_get_no_nudges(self):
        tid = self.task()
        self.control(tid, "pause")
        self.alive("studio", seen=1000)
        hub.q("UPDATE tasks SET last_activity=0 WHERE id=?", (tid,))
        hub.tick()
        t = hub.q1("SELECT * FROM tasks WHERE id=?", (tid,))
        self.assertEqual((t["live_path"], t["nudge_level"]), ("paused by the owner", 0))
        self.assertIn("HELD: paused by the owner", hub.overview_text())

    # ---- 5. task start
    def records_of_new_tasks(self):
        return [hub.q1(f"SELECT count(*) AS n FROM {table}")["n"] for table in ("tasks", "attempts", "events")]

    def test_a_new_task_its_first_attempt_and_its_start_event_are_written_together(self):
        text, error = hub.call_tool("manager", "create_task", {"owner": "studio", "title": "Send the note once",
                                                               "done_when": "outbox has it", "needs": "browser"})
        self.assertFalse(error, text)
        t = hub.q1("SELECT * FROM tasks")
        self.assertEqual(text, f"Created T-{t['id']} for studio. Note: studio's helper has not checked in recently.")
        self.assertEqual((t["owner"], t["requester"], t["state"], t["attempt"], t["last_activity"]),
                         ("studio", "manager", "submitted", 1, t["created"]))
        self.assertEqual([tuple(r) for r in hub.q("SELECT task, attempt, created, reason FROM attempts")],
                         [(t["id"], 1, t["created"], "created")])
        e = hub.q1("SELECT * FROM events")
        self.assertEqual((e["agent"], e["kind"], e["task"], e["text"], e["created"]),
                         ("studio", "task", t["id"], hub.start_text("studio", t["id"]), t["created"]))
        self.assertEqual(json.loads(e["extra"]), {"needs": "browser", "resume": False, "attempt": 1, "generation": "gen1"})
        self.assertEqual(self.records_of_new_tasks(), [1, 1, 1])
        self.assertEqual([x["kind"] for x in self.delivered("studio")], ["task"])

    def test_a_failed_later_write_leaves_no_task_attempt_or_start_event(self):
        class FailAt:
            """hub.DB with one failing INSERT: an interruption between the writes of a new task."""
            def __init__(self, db, table):
                self.db, self.table = db, table

            def execute(self, sql, *args):
                if sql.startswith(f"INSERT INTO {self.table}("):
                    raise sqlite3.OperationalError("disk I/O error")
                return self.db.execute(sql, *args)

            def __getattr__(self, name):
                return getattr(self.db, name)

        args = {"owner": "studio", "title": "Send the note once", "done_when": "outbox has it"}
        for table in ("attempts", "events"):
            with self.subTest(table=table), patch.object(hub, "DB", FailAt(hub.DB, table)):
                with self.assertRaises(sqlite3.OperationalError):
                    hub.call_tool("manager", "create_task", args)
                self.assertFalse(hub.DB.in_transaction)
                self.assertEqual(self.records_of_new_tasks(), [0, 0, 0])
        text, error = hub.call_tool("manager", "create_task", args)     # the next write commits nothing left over
        self.assertFalse(error, text)
        self.assertEqual(self.records_of_new_tasks(), [1, 1, 1])
        self.assertEqual([tuple(r) for r in hub.q("SELECT t.state, a.reason, e.kind FROM tasks t JOIN attempts a "
                                                  "ON a.task=t.id JOIN events e ON e.task=t.id")],
                         [("submitted", "created", "task")])


if __name__ == "__main__":
    unittest.main()

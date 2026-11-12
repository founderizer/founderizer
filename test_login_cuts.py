"""A text that is kept or shown before a later mask reads it is cut where no login can be cut in two (hub.cut_whole).

The masks (scrub, mask_secrets) find a registered login only whole, and a login can be registered after the text that
holds it was written: a part of one in a kept copy, or in a text that is cut before the mask of its answer, stays.
Release 2026.11.326 fixed five such cuts; these are the others (11 November 2026). Each test writes a text with a
login lying across one cut, registers the login after that text, and reads the copy or the answer through the mask.
In-process hub and temporary Git repositories; no helper, vault, GitHub, Google or AI call."""
import hashlib
import json
import unittest
import uuid

import hub
from test_blocked_access import BlockedAccess


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Cuts(name) for name in Cuts.__dict__ if name.startswith("test_"))


def across(cut, login, before=10):
    """Words, then `login` from `before` characters before the cut on, then more words."""
    assert cut > before + 1, (cut, before)
    return ("w " * cut)[:cut - before - 1] + " " + login + " and the words after it"


def register(login):
    """The owner registers `login` now: the hub keeps its salted hash and its length (POST /secrets)."""
    salt = "c0ffee"
    hub.ins("INSERT INTO secrets(label,salt,hash,len,username) VALUES(?,?,?,?,'')",
            (f"login-{login[:6]}", salt, hashlib.sha256((salt + login).encode()).hexdigest(), len(login)))


def assert_no_part(test, text, login):
    """No piece of the login: neither its first six characters nor its last six."""
    test.assertNotIn(login[:6], text)
    test.assertNotIn(login[-6:], text)


class Cuts(BlockedAccess):
    def register(self, login):
        register(login)

    def no_part(self, text, login):
        assert_no_part(self, text, login)

    def admitted(self, owner="dev", **fields):
        """A task through the hub's own admission, which keeps its start text."""
        f = dict({"owner": owner, "title": "Ship the shop page", "details": "", "done_when": "It is live.",
                  "needs": "none", "goal": None, "goal_id": None, "parent": None, "follows": None, "case_id": None,
                  "why": "The test."}, **fields)
        with hub.transaction():
            return hub.admit_task(hub.reports_to(owner) or "manager", f)

    def kept_start(self, tid, agent="dev"):
        return hub.q1("SELECT text FROM events WHERE agent=? AND kind='task' AND task=? ORDER BY id DESC LIMIT 1",
                      (agent, tid))["text"]

    def goal(self, text):
        t0 = hub.now()
        return hub.ins("INSERT INTO goals(title,text,state,revision,limits,created,updated,request_id) "
                       "VALUES('Grow the shop',?,'active',1,?,?,?,?)",
                       (text, json.dumps({"money": None, "tokens": None, "deadline": None, "not_to_do": []}), t0, t0,
                        str(uuid.uuid4())))

    # ---- clip, and what it cuts for the start texts, the messages and the history

    def test_clip_cuts_where_no_login_is_cut_in_two(self):
        login = "LqClip-7f3e9a01b2"
        line = hub.clip(across(180, login), 180)
        self.register(login)
        self.no_part(hub.mask_secrets(line), login)
        self.assertTrue(line.endswith(" w..."), line)
        short = "w " * 85 + "abcdefg hij"                       # a run of 7 across the cut is cut as before
        self.assertEqual(hub.clip(short, 175), short[:175] + "...")

    def test_a_note_carried_into_the_start_of_a_task_that_follows_keeps_no_part_of_a_login(self):
        login = "LqNote-7f3e9a01b2"
        first = self.admitted(title="Find the broken page")
        hub.ins("INSERT INTO notes(task,agent,ts,text) VALUES(?,?,?,?)", (first, "dev", hub.now(), across(180, login)))
        hub.q("UPDATE tasks SET state='completed', what='Found it.' WHERE id=?", (first,))
        second = self.admitted(title="Fix the broken page", follows=first)
        self.register(login)
        kept = self.kept_start(second)
        self.assertIn("What its agent wrote down (1 note(s), the last 1):", kept)
        self.no_part(kept, login)

    # ---- a task's own start

    def test_the_details_in_a_kept_start_keep_no_part_of_a_login(self):
        login = "LqDetail-7f3e9a01b2"
        tid = self.admitted(details=across(hub.TASK_DETAILS_CHARS, login))
        self.register(login)
        kept = self.kept_start(tid)
        self.assertIn("(list_my_tasks gives the rest)", kept)
        self.no_part(kept, login)

    def test_the_goal_words_that_list_my_tasks_gives_keep_no_part_of_a_login(self):
        login = "LqGoal-7f3e9a01b2"
        tid = self.admitted(goal_id=self.goal(across(hub.GOAL_WHY_CHARS, login)))
        self.register(login)
        said = self.ok("dev", "list_my_tasks", {"task_id": hub.tref(tid)}, tid)
        self.assertIn("The goal says more than this.", said)
        self.no_part(said, login)

    def test_the_last_words_of_a_turn_keep_no_part_of_a_login(self):
        login = "LqSaid-7f3e9a01b2"
        state = hub.turn_records(None, "s-1", [(1, None, "agent_message", {"text": across(hub.TURN_SAID, login)})],
                                 hub.now())
        self.register(login)
        self.no_part(hub.mask_secrets(state["said"]), login)
        state = hub.turn_records(None, "s-2", [(1, None, "agent_message", {"text": "x" * 600})], hub.now())
        self.assertEqual(state["said"], "...")              # one run: none of it, and its requester reads no "nothing"

    def test_a_refused_permission_named_in_the_start_after_a_restart_keeps_no_part_of_a_login(self):
        login = "LqPrompt-7f3e9a01b2"
        tid = self.task_for("dev")
        hub.ins("INSERT INTO prompts(task,agent,tool,input,key,created,decision,reason,decided,by,kind) "
                "VALUES(?,?,'Bash',?,'k',?,'deny','no',?,'manager','tool')",
                (tid, "dev", across(100, login), hub.now(), hub.now()))
        self.register(login)
        text, error = self.restart(tid)
        self.assertFalse(error, text)
        self.stop_confirmed(tid)
        kept = self.kept_start(tid)
        self.assertIn("These permission requests of this task were refused", kept)
        self.no_part(kept, login)

    def test_the_error_of_a_screen_session_told_to_the_requester_keeps_no_part_of_a_login(self):
        login = "LqScreen-7f3e9a01b2"
        tid = self.admitted(needs="screen")
        with hub.LOCK:
            hub.screen_failed((tid, 1, "s-1"), 3, {"message": across(300, login)})
        said = self.said_to("manager")
        self.assertIn("ended with an error that a new session does not correct by itself", said)
        self.register(login)
        self.no_part(hub.mask_secrets(said), login)
        other = self.admitted(needs="screen", title="Check the shop page")
        with hub.LOCK:
            hub.screen_failed((other, 1, "s-2"), 3, {"message": "x" * 290 + login})
        self.assertIn("The error: ... T-", self.said_to("manager"))      # one run: none of it, and not "no error"

    # ---- call_api, Gmail and Google reads

    def test_a_requests_path_in_a_message_and_in_an_outcome_keeps_no_part_of_a_login(self):
        login = "LqPath-7f3e9a01b2"
        tid = self.task_for("dev")
        path = "/v1/items?q=" + "x" * 98 + login             # one run: it is left out from where it starts
        job = {"kind": "request", "method": "GET", "path": path, "login": "crm", "request_id": "r-1", "task": tid,
               "attempt": 1, "id": 1}
        said = hub.job_what(job)
        with hub.transaction():
            hub.request_unknown_rows(job)
        title = hub.q1("SELECT title FROM outcomes WHERE task=?", (tid,))["title"]
        self.register(login)
        for text in (said, title):
            self.no_part(hub.mask_secrets(text), login)
        self.assertEqual(said, f"call_api GET a path of {len(path)} characters with crm (request_id r-1)")
        spaced = {**job, "path": across(120, login)}
        self.assertTrue(hub.job_what(spaced).startswith("call_api GET w w w"))

    def test_a_google_read_cut_before_its_mask_shows_no_part_of_a_login(self):
        login = "LqDrive-7f3e9a01b2"
        text = across(hub.GOOGLE_TEXT_MAX, login)
        self.register(login)
        said = hub.google_data("drive", "owner@example.com", hub.google_cut(text)[0])
        self.no_part(said, login)
        self.assertIn(hub.MASK[:10] + f"\n[Cut: this text has {len(text):,} characters. You see the first "
                      f"{hub.GOOGLE_TEXT_MAX:,}.]", said)
        run = "x" * 60000 + " " + login                 # one run with no space keeps its first characters
        self.assertTrue(hub.google_cut(run)[0].startswith("x" * hub.GOOGLE_TEXT_MAX + "\n[Cut: "))
        edge = hub.GOOGLE_TEXT_MAX + hub.MASK_PAST_CUT  # a login across the end of what is masked is not shown
        said = hub.google_cut(across(edge, login))[0]
        self.assertTrue(said.startswith("w w") and len(said) > hub.GOOGLE_TEXT_MAX)
        self.no_part(said, login)

    # ---- refusals: the answer is masked after them, and calls keeps them

    def test_a_refusal_that_names_the_linked_tasks_shows_no_part_of_a_login_in_a_title(self):
        login = "LqTitle-7f3e9a01b2"
        for _ in range(2):
            self.admitted(title=across(60, login))
        self.register(login)
        with self.assertRaises(hub.ToolError) as caught:
            hub.linked_choice("manager", None, "dev", None)
        said = hub.mask_secrets(str(caught.exception))
        self.assertIn("Your message could go to 2 tasks of dev", said)
        self.no_part(said, login)

    def test_a_refused_option_of_a_needs_you_item_shows_no_part_of_a_login(self):
        login = "LqOption-7f3e9a01b2"
        self.register(login)
        with self.assertRaises(hub.ToolError) as caught:
            hub.check_need_options(["Yes", across(60, login) + " " + "z " * 40])
        self.no_part(hub.mask_secrets(str(caught.exception)), login)
        with self.assertRaises(hub.ToolError) as caught:
            hub.check_need_options(["Yes", "x" * 130])
        self.assertIn("characters: shorten the option of 130 characters or leave", str(caught.exception))

    def test_a_refused_message_to_no_agent_shows_no_part_of_a_login(self):
        login = "LqTo-7f3e9a01b2"
        self.register(login)
        _, said = hub.agent_message_refusal("dev", across(40, login), None, hub.now())
        self.assertIn("Refused: there is no active agent named w w", said)
        self.no_part(hub.mask_secrets(said), login)
        _, said = hub.agent_message_refusal("dev", "x" * 30 + login, None, hub.now())
        self.assertIn("Refused: there is no active agent of that name.", said)

    def test_the_log_keeps_a_refusal_as_its_answer_has_it(self):
        """A refusal can quote what the agent wrote. call_tool masks it for the answer and for calls.detail, and the
        log line keeps that same text, so the log holds no login that was registered when the call came. A refusal
        with no login is logged as it was."""
        login = "LqRefused-7f3e9a01b2"
        self.register(login)
        said, refused = hub.call_tool("manager", "message_agent", {"agent": login, "text": "Hello.",
                                                                  "request_id": str(uuid.uuid4())})
        self.assertTrue(refused, said)
        self.assertIn(f"Refused: there is no active agent named {hub.MASK} The agents are:", said)
        last = "SELECT what FROM log WHERE what LIKE 'message_agent refused: %' ORDER BY id DESC LIMIT 1"
        self.assertEqual(hub.q1(last)["what"], "message_agent refused: " + said)
        self.assertEqual(hub.q1("SELECT detail FROM calls ORDER BY id DESC LIMIT 1")["detail"], said)
        self.no_part(hub.q1(last)["what"], login)
        said, refused = hub.call_tool("manager", "message_agent", {"agent": "nobody-here", "text": "Hello.",
                                                                  "request_id": str(uuid.uuid4())})
        self.assertTrue(refused, said)
        self.assertIn("Refused: there is no active agent named nobody-here.", said)
        self.assertEqual(hub.q1(last)["what"], "message_agent refused: " + said)

    # ---- kept records

    def test_a_log_line_keeps_no_part_of_a_login(self):
        """A log line is cut at LOG_MOST characters, and it can quote what an agent wrote: leak_scan reads log.what
        and finds a login only whole. A line with no long run across the cut is cut as before."""
        def in_a_transaction(agent, what):
            with hub.transaction():
                hub.log_row(agent, what)
        for n, write in enumerate((hub.log, in_a_transaction)):
            login = f"LqLogLine{n}-7f3e9a01b2"
            write("dev", across(hub.LOG_MOST, login))
            self.register(login)
            line = hub.q1("SELECT what FROM log ORDER BY id DESC LIMIT 1")["what"]
            self.no_part(line, login)
            self.assertTrue(line.endswith(" w"), line[-20:])
        short = "w " * 199 + "abcdefg hij"                              # a run of 7 across the cut is cut as before
        hub.log("dev", short)
        self.assertEqual(hub.q1("SELECT what FROM log ORDER BY id DESC LIMIT 1")["what"], short[:hub.LOG_MOST])

    def test_a_goal_change_keeps_no_part_of_a_login(self):
        login = "LqGoalLog-7f3e9a01b2"
        gid = self.goal("Grow the shop.")
        hub.goal_history(gid, "manager", "edited", across(2000, login))
        self.register(login)
        self.no_part(hub.mask_secrets(hub.q1("SELECT detail FROM goal_history WHERE goal=?", (gid,))["detail"]), login)

    def test_a_lesson_in_a_start_keeps_no_part_of_a_login(self):
        login = "LqLesson-7f3e9a01b2"
        digest = hub.memory_said({"text": across(120, login)}, "text", 120)
        lesson = {"id": 4, "text": "y" * 60 + login + " is the key of the crm", "about": "crm", "read_untrusted": 0,
                  "contradicted": 0}
        line = hub.memory_index_line(lesson)
        self.register(login)
        for text in (digest, line):
            self.no_part(hub.mask_secrets(text), login)
        self.assertEqual(line, "  M-4 [crm] …")

    def test_an_argument_of_a_call_in_the_history_keeps_no_part_of_a_login(self):
        login = "LqArg-7f3e9a01b2"
        said = hub.history_flat({"to": "dev", "text": across(2000, login)})
        self.register(login)
        self.no_part(hub.mask_secrets(said), login)

    def test_a_session_record_keeps_no_part_of_a_login(self):
        login = "LqRecord-7f3e9a01b2"
        record = hub.clean_record({"seq": 1, "ts": hub.now(), "type": "agent_message", "text": across(3999, login)})
        self.assertTrue(record[3]["text"].endswith("…"))
        self.register(login)
        self.no_part(hub.mask_secrets(record[3]["text"]), login)

    def test_a_session_record_that_the_helper_cut_keeps_no_part_of_a_login(self):
        """The helper cuts each record at the hub's own limits before it sends it: threads.clip with a closing "…",
        acp_runner with none. A text that arrives at its limit loses the run that it ends in."""
        import threads
        login = "LqHelper-7f3e9a01b2"
        said = threads.clip(across(threads.TEXT - 1, login, before=3), threads.TEXT)    # a Claude or Codex transcript
        self.assertEqual((len(said), said[-4:]), (threads.TEXT, login[:3] + "…"))
        message = hub.clean_record({"seq": 1, "type": "agent_message", "text": said})
        output = hub.clean_record({"seq": 2, "type": "tool_call", "tool_call_id": "c-1", "title": "Bash: curl",
                                   "kind": "execute", "status": "completed",
                                   "output": across(800, login, before=3)[:800]})          # acp_runner's own cut
        self.register(login)
        self.assertTrue(message[3]["text"].endswith(" w…"), message[3]["text"][-20:])
        for text in (message[3]["text"], output[3]["output"]):
            self.assertNotIn(login[:3], hub.mask_secrets(text))
        spawned = hub.clean_record({"seq": 4, "type": "tool_call", "tool_call_id": "c-2", "title": "Agent: look",
                                    "kind": "other", "status": "in_progress",       # threads.py: its type or its task
                                    "subagent": {"name": across(100, login, before=3)[:100]}})
        self.assertNotIn(login[:3], spawned[3]["subagent"]["name"])
        # an id, which the helper never cuts so, comes as it is at its limit
        self.assertEqual(hub.clean_record({"seq": 3, "type": "session", "runtime": "claude-code-agent-12",
                                           "session_id": "s" * 80})[3], {"runtime": "claude-code-agent-12",
                                                                          "session_id": "s" * 80})

    def test_a_session_record_kept_before_this_release_loses_the_part_at_its_end(self):
        """Until 11 November 2026 a record that arrived at its limit, cut there by the helper, was kept as it came. At
        the start, records_recut takes the run that such a text ends in out of it, from the id that the last pass
        finished on: a row that an older release writes after a rollback goes at the next start."""
        login = "LqOldRecord-7f3e9a01b2"
        tid = self.task_for("dev")

        def row(seq, kind, data):
            return hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) "
                           "VALUES(?,1,'s-1',?,?,?,?,?)", (tid, seq, hub.now(), kind, json.dumps(data), hub.now()))

        cut = across(4000, login, before=3)[:4000]                  # as acp_runner sent it, with no closing mark
        # threads.clip's title of a command on two lines, which the older text_field kept shorter, its lines joined
        joined = " ".join(((("w  " * 300)[:285] + " " + login + " more")[:299] + "…").split())
        ids = [row(1, "agent_message", {"text": cut}),
               row(2, "tool_call", {"tool_call_id": "c-1", "status": "completed", "kind": "execute",
                                    "title": across(300, login)[:299] + "…", "output": across(800, login)[:800]}),
               row(3, "agent_message", {"text": "a short message"}),
               row(4, "agent_thought", {"text": across(2000, login)[:1999] + "…"}),
               row(5, "plan", {"entries": [{"content": across(300, login)[:300], "status": "pending"}]}),
               row(6, "tool_call", {"tool_call_id": "c-2", "status": "completed", "kind": "execute", "title": joined,
                                    "subagent": {"name": across(100, login)[:99] + "…"}})]
        self.assertLess(len(joined), 300)
        hub.records_recut()
        self.register(login)
        data = [json.loads(hub.q1("SELECT data FROM thread_events WHERE id=?", (i,))["data"]) for i in ids]
        for text in (data[0]["text"], data[1]["title"], data[1]["output"], data[3]["text"],
                     data[4]["entries"][0]["content"], data[5]["title"], data[5]["subagent"]["name"]):
            self.assertTrue(text.endswith(" w…"), text[-20:])
            self.assertNotIn(login[:3], hub.mask_secrets(text))
        self.assertEqual(data[2], {"text": "a short message"})
        self.assertEqual((hub.kv_get("records_recut"), hub.kv_get("records_recut_until")), (str(ids[-1]),) * 2)
        later = row(7, "agent_message", {"text": cut})            # an older release's row, after a rollback
        new = row(8, "agent_message", {"text": "this code cut it where no login is cut in two w w…"})
        hub.records_recut()
        self.assertTrue(json.loads(hub.q1("SELECT data FROM thread_events WHERE id=?", (later,))["data"])["text"]
                        .endswith(" w…"))
        self.assertEqual(json.loads(hub.q1("SELECT data FROM thread_events WHERE id=?", (new,))["data"])["text"],
                         "this code cut it where no login is cut in two w w…")      # after the first start: as it is

    def test_the_last_error_line_of_a_fleet_check_keeps_no_part_of_a_login(self):
        login = "LqCheck-7f3e9a01b2"
        said = hub.check_said({"path": "checks/pool.py"}, {"tail": "first\n" + across(hub.CHECK_SAID, login)})
        self.register(login)
        self.no_part(hub.mask_secrets(said), login)

    def test_the_reports_named_to_a_manager_that_starts_again_keep_no_part_of_a_login(self):
        login = "LqReport-7f3e9a01b2"
        t0 = hub.now()
        eid = hub.ins("INSERT INTO events(agent,kind,task,text,created,extra,read_at) VALUES('manager','say',NULL,"
                      "'[owner] Ship it.',?,'{}',?)", (t0, t0))
        hub.ins("INSERT INTO owner_reports(text,about,agent,created) VALUES(?,'shop','manager',?)",
                (across(300, login), t0 + 1))
        said = hub.reports_since("manager", [eid])
        self.register(login)
        self.no_part(hub.mask_secrets(said), login)

    # ---- the chat apps

    def test_the_preview_of_an_ignored_chat_message_keeps_no_part_of_a_login(self):
        login = "LqChat-7f3e9a01b2"
        hub.TEAM["chat_apps"] = {"discord-shop": {"app": "discord", "label": "Shop", "agents": ["dev"],
                                                  "unknown": "ignore"}}
        m = hub.inbound_message({"account": "discord-shop", "id": "m-1", "chat": "c-1", "sender": "u-9",
                                 "sender_name": "Ana", "group": False, "bot": False, "from_me": False,
                                 "kind": "text", "text": across(200, login)})
        self.assertEqual(hub.chat_inbound(m), "ignored")
        preview = hub.q1("SELECT preview FROM chat_ignored")["preview"]
        self.register(login)
        self.no_part(hub.mask_secrets(preview), login)
        # The preview masks the first 1000 characters before it takes 200 of them: a long login masked there brings a
        # second one from across that first cut into the preview, so the first cut is made where no login is cut too.
        token, later = "LqToken" + "t" * 893, "LqLater-7f3e9a01b2"
        self.register(token)
        self.register(later)
        text = token + " " + across(1000 - len(token) - 1, later)
        m = dict(m, id="m-2", text=text)
        self.assertEqual(hub.chat_inbound(m), "ignored")
        preview = hub.q1("SELECT preview FROM chat_ignored ORDER BY id DESC LIMIT 1")["preview"]
        self.assertTrue(preview.startswith(hub.MASK + " w w"), preview)
        self.no_part(preview, later)

    # ---- what the helper reports

    def helper(self, path, body):
        code, answer = self.request(path, body, source=hub.TEAM["addresses"]["devbox"])
        self.assertEqual(code, 200, answer)
        return answer

    def test_the_files_that_the_helper_did_not_send_keep_no_part_of_a_login(self):
        login = "LqUnsent-7f3e9a01b2"
        tid = self.task_for("dev")
        token = str(uuid.uuid4())
        with hub.OUTPUTS_LOCK:
            hub.OUTPUTS[token] = {"agent": "dev", "task": tid, "answer": None, "gave_up": False, "late": False}
        self.addCleanup(hub.OUTPUTS.pop, token, None)
        self.helper("/helper/outputs/dev", {"outputs": token, "task": hub.tref(tid), "files": [],
                                           "skipped": [{"path": across(200, login), "why": "a symbolic link"},
                                                       {"path": "x" * 200 + login, "why": "too large"}]})
        said = hub.outputs_sentence("dev", hub.get_task(tid), hub.OUTPUTS[token]["answer"])
        self.assertIn("; … (too large).", said)
        self.register(login)
        self.no_part(hub.mask_secrets(said), login)

    def test_a_delivery_and_a_withdrawal_report_keep_no_part_of_a_login(self):
        login = "LqVault-7f3e9a01b2"
        t0 = hub.now()
        did = hub.ins("INSERT INTO deposits(login,machine,agent,recipient,sha256,request_id,created) "
                      "VALUES('bws://x','devbox','dev','age1','s',?,?)", (str(uuid.uuid4()), t0))
        wid = hub.ins("INSERT INTO withdrawals(login,machine,agent,created) VALUES('bws://x','devbox','dev',?)", (t0,))
        self.helper(f"/helper/deposit/dev/{did}", {"ok": False, "text": across(hub.DEPOSIT_RESULT_MAX, login)})
        self.helper(f"/helper/withdraw/dev/{wid}", {"ok": False, "text": across(hub.DEPOSIT_RESULT_MAX, login)})
        # the helper cuts the vault's refusal at the same 300 characters before it sends it (Helper.deposit)
        sent = across(hub.DEPOSIT_RESULT_MAX, login, before=3)[:hub.DEPOSIT_RESULT_MAX]
        again = hub.ins("INSERT INTO deposits(login,machine,agent,recipient,sha256,request_id,created) "
                        "VALUES('bws://x','devbox','dev','age1','s',?,?)", (str(uuid.uuid4()), t0))
        self.helper(f"/helper/deposit/dev/{again}", {"ok": False, "text": sent})
        self.assertTrue(hub.q1("SELECT result FROM deposits WHERE id=?", (again,))["result"].endswith(" w"))
        told = [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' AND "
                                         "text LIKE '%vault of devbox%' ORDER BY id")]
        self.assertEqual(len(told), 3, told)
        self.register(login)
        for text in told + [r["result"] for r in hub.q("SELECT result FROM deposits UNION ALL "
                                                       "SELECT result FROM withdrawals")]:
            self.no_part(hub.mask_secrets(text), login)
            self.assertNotIn(login[:3], hub.mask_secrets(text))

    def test_a_helper_report_of_a_job_keeps_no_part_of_a_login(self):
        login = "LqJob-7f3e9a01b2"
        tid = self.task_for("dev")
        t0 = hub.now()
        first = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES('dev',?,'signin','crm','',?)",
                        (tid, t0))
        lost = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES('dev',?,'signin','crm','',?)",
                       (tid, t0))
        third = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created) VALUES('dev',?,'signin','crm','',?)",
                        (tid, t0))
        hub.ins("INSERT INTO outcomes(task,attempt,hold,tool_call_id,title,kind,state,created) "
                "VALUES(?,1,0,?,'a sign-in','other','unknown',?)", (tid, f"job-{lost}", t0))
        self.helper(f"/helper/job/dev/{first}", {"ok": False, "text": across(600, login)})
        self.helper(f"/helper/job/dev/{lost}", {"ok": True, "text": across(200, login)})
        self.helper(f"/helper/job/dev/{third}", {"ok": False, "text": "x" * 590 + login})
        self.assertEqual(hub.q1("SELECT result FROM jobs WHERE id=?", (third,))["result"], "...")    # not "done"
        kept = [hub.q1("SELECT result FROM jobs WHERE id=?", (first,))["result"],
                hub.q1("SELECT note FROM outcomes WHERE tool_call_id=?", (f"job-{lost}",))["note"]]
        self.assertTrue(kept[1].startswith("the helper reported it: w w"), kept[1])
        self.register(login)
        for text in kept:
            self.no_part(hub.mask_secrets(text), login)

    def test_the_kept_answer_of_a_request_keeps_no_part_of_a_login_and_a_compact_body_whole(self):
        login = "LqAnswer-7f3e9a01b2"
        tid = self.task_for("dev")

        def answered(body, **more):
            jid = hub.ins("INSERT INTO jobs(agent,task,kind,login,target,created,request_id,attempt,method,path,"
                          "released) VALUES('dev',?,'request','crm','',?,?,1,'GET','/v1/items',?)",
                          (tid, hub.now(), str(uuid.uuid4()), hub.now()))
            self.helper(f"/helper/job/dev/{jid}", dict({"ok": True, "status": 200, "body": body}, **more))
            return hub.q1("SELECT response, result FROM jobs WHERE id=?", (jid,))

        spaced = answered(across(hub.API_ANSWER, login))
        compact = json.dumps([{"id": n, "name": f"item-{n}"} for n in range(1800)], separators=(",", ":"))
        self.assertTrue(hub.API_ANSWER < len(compact) <= 2 * hub.API_ANSWER)        # one run, as the vault sends
        whole = answered(compact)
        cut = answered(compact, truncated=True)
        wide = "语" * 21000 + " " + login       # 63,000 bytes and more: the vault cut it inside the login
        vault = answered(wide[:21000 + 1 + 12], truncated=True)
        self.register(login)
        self.no_part(hub.mask_secrets(spaced["response"]), login)
        self.no_part(hub.mask_secrets(vault["response"]), login)
        self.assertEqual((spaced["result"], whole["response"], whole["result"]),
                         ("HTTP 200. The body was cut.", compact, "HTTP 200."))
        self.assertEqual((cut["response"], cut["result"]), ("", "HTTP 200. The body was cut. None of it is kept: it is one "
                                                           "run of characters with no space across the cut, and a part "
                                                           "of it could be part of a login. Ask for less of it."))
        self.assertEqual(vault["response"], "语" * 21000)


if __name__ == "__main__":
    unittest.main()

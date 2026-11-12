"""Deterministic checks of runtime thread records. Real-format lines, no AI calls, no hub."""
import json
import os
import tempfile
import unittest
from unittest import mock

import threads

SESSION = "0b7d5a8e-3c1f-4e2a-9d6b-1f2e3d4c5b6a"


def lines(rows):
    return [json.dumps(r) for r in rows]


def translate(runtime, rows):
    tr = threads.Translator(runtime)
    out = []
    for row in rows:
        out.extend(tr.records(row))
    return out, tr


CLAUDE = [
    {"type": "user", "sessionId": SESSION, "timestamp": "2026-10-10T08:00:00.000Z",
     "message": {"role": "user", "content": "You are agent \"studio\". Your task is T-7."}},
    {"type": "user", "isMeta": True, "sessionId": SESSION, "message": {"content": "caveat text"}},
    {"type": "assistant", "sessionId": SESSION, "timestamp": "2026-10-10T08:00:01.000Z",
     "message": {"content": [{"type": "thinking", "thinking": "I should read the task.", "signature": "x" * 50}]}},
    {"type": "assistant", "sessionId": SESSION, "message": {"content": [{"type": "text", "text": "I will run the test."}]}},
    {"type": "assistant", "sessionId": SESSION, "message": {"content": [
        {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "pytest -q\nsecond line", "description": "tests"}}]}},
    {"type": "user", "sessionId": SESSION, "message": {"content": [
        {"type": "tool_result", "tool_use_id": "toolu_1", "content": [{"type": "text", "text": "3 passed"}], "is_error": False}]}},
    {"type": "assistant", "sessionId": SESSION, "message": {"content": [
        {"type": "tool_use", "id": "toolu_2", "name": "TodoWrite", "input": {"todos": [
            {"content": "Run tests", "status": "completed", "activeForm": "Running"},
            {"content": "Deliver", "status": "in_progress", "activeForm": "Delivering"}]}}]}},
    {"type": "user", "sessionId": SESSION, "message": {"content": [
        {"type": "tool_result", "tool_use_id": "toolu_2", "content": "Todos updated"}]}},
    {"type": "assistant", "sessionId": SESSION, "message": {"content": [
        {"type": "tool_use", "id": "toolu_3", "name": "mcp__fleet__report_progress", "input": {"task_id": "T-7", "note": "ran"}}]}},
    {"type": "assistant", "sessionId": SESSION, "isSidechain": True, "message": {"content": [{"type": "text", "text": "subagent"}]}},
    {"type": "assistant", "sessionId": SESSION, "message": {"content": [
        {"type": "tool_use", "id": "toolu_4", "name": "Bash", "input": {"command": "curl -X POST hub/outbox"}}]}},
    {"type": "user", "sessionId": SESSION, "message": {"content": [
        {"type": "tool_result", "tool_use_id": "toolu_4", "content": "[Request interrupted by user for tool use]", "is_error": True}]}},
    {"type": "user", "sessionId": SESSION, "message": {"content": [{"type": "text", "text": "[Request interrupted by user for tool use]"}]}},
    {"type": "system", "subtype": "turn_duration", "sessionId": SESSION},
    {"type": "assistant", "sessionId": SESSION, "isApiErrorMessage": True, "error": "rate_limit", "apiErrorStatus": 429,
     "quotaLimits": {"status": "rejected", "resetsAt": 1790700600, "rateLimitType": "five_hour"},
     "message": {"model": "<synthetic>", "content": [{"type": "text", "text": "You've hit your session limit - resets 6:50pm"}]}},
    {"type": "assistant", "sessionId": SESSION, "isApiErrorMessage": True, "error": "rate_limit", "apiErrorStatus": 429,
     "message": {"content": [{"type": "text", "text": "API Error: 429"}]}},
    {"type": "assistant", "sessionId": SESSION, "isApiErrorMessage": True, "error": "server_error", "apiErrorStatus": 529,
     "message": {"content": [{"type": "text", "text": "API Error: 529 Overloaded."}]}},
]

CODEX = [
    {"timestamp": "2026-10-10T09:00:00.000Z", "type": "session_meta", "payload": {"id": "01a1-codex", "cwd": "/kit"}},
    {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "UserMessage", "id": "u1",
        "content": [{"type": "text", "text": "Your task is T-8.\n\n" + threads.MARKER.format(SESSION)}]}}},
    {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "Reasoning", "id": "r1",
        "summary_text": ["Plan the work"], "raw_content": []}}},
    {"type": "response_item", "payload": {"type": "function_call", "name": "update_plan", "call_id": "call_p",
        "arguments": json.dumps({"plan": [{"step": "Write file", "status": "in_progress"}]})}},
    {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "call_p", "output": "ok"}},
    {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "call_1",
        "input": "echo hi > out.txt", "status": "completed"}},
    {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "CommandExecution", "id": "c1",
        "command": ["bash -lc 'false'"], "parsed_cmd": [{"type": "unknown", "cmd": "false"}], "status": "completed",
        "exit_code": 1, "aggregated_output": ""}}},
    {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "McpToolCall", "id": "m1", "server": "fleet",
        "tool": "report_progress", "arguments": {"task_id": "T-8"}, "readOnlyHint": False, "status": "completed",
        "result": {"content": [{"type": "text", "text": "Noted."}], "isError": False}}}},
    {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "call_1",
        "output": [{"type": "input_text", "text": "done"}]}},
    {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "AgentMessage", "id": "a1",
        "content": [{"type": "text", "text": "Finished."}], "phase": "final_answer"}}},
    {"type": "event_msg", "payload": {"type": "token_count", "rate_limits": {"primary": {"used_percent": 40.0,
        "window_minutes": 300, "resets_at": 1792154554}, "rate_limit_reached_type": None}}},
    {"type": "event_msg", "payload": {"type": "token_count", "rate_limits": {"primary": {"used_percent": 100.0,
        "window_minutes": 300, "resets_at": 1792154554}, "rate_limit_reached_type": "primary"}}},
    {"type": "event_msg", "payload": {"type": "token_count", "rate_limits": {"primary": {"used_percent": 100.0,
        "window_minutes": 300, "resets_at": 1792154554}, "rate_limit_reached_type": "primary"}}},
    {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "Finished."}},
    {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "call_2", "input": "rm x"}},
]


def app(method, ts=1791640000.0, **params):
    """One line of a screen task's record file: a Codex app-server v2 notification as screen_runner.py writes it."""
    return {"timestamp": ts, "method": method, "params": params}


def app_item(method, item, turn="turn-1"):
    return app(method, threadId="thr-1", turnId=turn, item=item)


USER = {"type": "userMessage", "id": "u1", "clientId": None,
        "content": [{"type": "text", "text": "Your task is T-9.", "text_elements": []}]}
NOTE = {"type": "mcpToolCall", "id": "call_f1", "server": "fleet", "tool": "report_progress", "status": "inProgress",
        "arguments": {"task_id": "T-9", "note": "starting"}, "appContext": None, "mcpAppUi": None, "pluginId": None,
        "readOnlyHint": False, "result": None, "error": None, "durationMs": None}
CLICK = dict(NOTE, id="call_c1", server="cua_repl", tool="js", readOnlyHint=True,     # cua_repl calls every js call read-only
             arguments={"code": "await app.click(5);\nawait app.getScreenshot();"})
SHELL = {"type": "commandExecution", "id": "call_s1", "command": "/bin/zsh -lc 'ls outputs/T-9/computer-use'", "cwd": "/kit",
         "processId": None, "source": "agent", "status": "inProgress", "pluginId": None, "scriptPath": None,
         "commandActions": [{"type": "listFiles", "command": "ls outputs/T-9/computer-use", "path": "outputs/T-9/computer-use"}],
         "aggregatedOutput": None, "exitCode": None, "durationMs": None}
APP = [
    app_item("item/started", USER),
    app_item("item/completed", USER),
    app_item("item/completed", {"type": "reasoning", "id": "r1", "summary": ["Open Calculator first"], "content": ["raw"]}),
    app("turn/plan/updated", threadId="thr-1", turnId="turn-1", explanation=None, plan=[
        {"step": "Open Calculator", "status": "completed"}, {"step": "Compute 63 × 2", "status": "inProgress"}]),
    app_item("item/started", NOTE),
    app_item("item/completed", dict(NOTE, status="completed", durationMs=12,
             result={"content": [{"type": "text", "text": "Noted."}], "structuredContent": None, "_meta": None})),
    app_item("item/started", CLICK),
    app_item("item/completed", dict(CLICK, status="completed", result={"content": [
        {"type": "text", "text": "clicked"}, {"type": "image", "mimeType": "image/png"}]})),     # the runner removed the data
    app_item("item/started", SHELL),
    app_item("item/completed", dict(SHELL, status="failed", exitCode=1, aggregatedOutput="ls: No such file or directory")),
    app_item("item/completed", {"type": "fileChange", "id": "call_e1", "status": "completed", "changes": [
        {"path": "/kit/outputs/T-9/notes.md", "kind": {"type": "add"}, "diff": "+126"}]}),
    app_item("item/completed", {"type": "agentMessage", "id": "a1", "text": "126 is on the screen.", "phase": None,
                                "memoryCitation": None, "delivery": None, "questions": None}),
    app("turn/completed", threadId="thr-1", turn={"id": "turn-1", "rootTurnId": None, "items": [], "status": "completed",
                                                  "error": None, "startedAt": 1791640000, "completedAt": 1791640060}),
    app_item("item/started", dict(CLICK, id="call_c2", arguments={"code": "await app.click(9);"}), turn="turn-2"),
]


class Translation(unittest.TestCase):
    def test_claude_lines_become_acp_records(self):
        out, tr = translate("claude", CLAUDE)
        self.assertEqual([r["seq"] for r in out], list(range(1, len(out) + 1)))
        # one end for each turn: the interrupt ends the turn, so the turn_duration after it is no second end, and each
        # error that Claude Code shows ends its turn (plan C1)
        self.assertEqual([r["type"] for r in out], [
            "session", "user_message", "agent_thought", "agent_message", "tool_call", "tool_call_update", "plan",
            "tool_call", "tool_call", "tool_call_update", "result", "error", "result", "error", "result", "error",
            "result"])
        self.assertEqual(out[0]["session_id"], SESSION)
        self.assertEqual(out[0]["ts"], 1791619200.0)
        bash = out[4]
        self.assertEqual((bash["title"], bash["kind"], bash["status"], bash["server"]), ("Bash: pytest -q", "execute", "in_progress", None))
        self.assertEqual((out[5]["status"], out[5]["output"], out[5]["interrupted"]), ("completed", "3 passed", False))
        self.assertEqual(out[6]["entries"], [{"content": "Run tests", "status": "completed"},
                                             {"content": "Deliver", "status": "in_progress"}])
        fleet = out[7]
        self.assertEqual((fleet["title"], fleet["kind"], fleet["server"]), ("fleet: report_progress: T-7", "other", "fleet"))
        self.assertTrue(out[9]["interrupted"])
        self.assertEqual(out[9]["status"], "failed")
        self.assertEqual([out[n]["stop_reason"] for n in (10, 12, 14, 16)], ["cancelled", "error", "error", "error"])
        self.assertEqual((out[11]["code"], out[11]["resets_at"]), ("usage_limit", 1790700600.0))
        self.assertEqual((out[13]["code"], out[13]["resets_at"]), ("rate_limit", None))
        self.assertEqual((out[15]["code"], out[15]["retryable"]), ("server_error", True))
        self.assertEqual(tr.open, {"toolu_3"})          # the fleet call never got its result in these lines
        self.assertNotIn("subagent", json.dumps(out))
        self.assertNotIn("caveat", json.dumps(out))
        self.assertNotIn("signature", json.dumps(out))

    def test_claude_task_tools_are_its_plan(self):
        """Claude Code 2.1.3xx keeps its plan with TaskCreate and TaskUpdate, and offers TodoWrite only with its tasks
        off: each change of its list is one plan record, an update finds its task by the id that the creating call's
        result gave (its text, else toolUseResult), and none of the four tools shows as a call."""
        def use(call, name, **args):
            return {"type": "assistant", "sessionId": SESSION, "message": {"content": [
                {"type": "tool_use", "id": call, "name": name, "input": args}]}}

        def result(call, content, error=False, made=None):
            row = {"type": "user", "sessionId": SESSION, "message": {"content": [
                {"type": "tool_result", "tool_use_id": call, "content": content, "is_error": error}]}}
            return dict(row, toolUseResult={"task": {"id": made, "subject": "s"}}) if made else row

        rows = [use("t1", "TaskCreate", subject="Read the advisories", description="All", activeForm="Reading"),
                use("t2", "TaskCreate", subject="Upgrade the apps", description="Seven"),
                result("t1", "Task #1 created successfully: Read the advisories", made="1"),
                result("t2", [{"type": "text", "text": "Task #2 created successfully: Upgrade the apps"}]),
                use("t3", "TaskUpdate", taskId="1", status="in_progress"), result("t3", "Updated task #1 status"),
                use("t4", "TaskUpdate", taskId="1", status="completed"),
                use("t5", "TaskUpdate", taskId="2", subject="Upgrade the seven apps", status="in_progress"),
                use("t6", "TaskList"), use("t7", "TaskGet", taskId="2"),
                use("t8", "TaskUpdate", taskId="9", status="completed"),       # a task this session never made
                use("t9", "TaskUpdate", taskId="2", description="New words"),  # no change that the plan shows
                use("t10", "TaskCreate", subject="Refused", description="x"), result("t10", "Invalid input", error=True),
                use("t11", "TaskCreate", subject="Spare", description="x"), result("t11", "", made="3"),
                use("t12", "TaskUpdate", taskId="3", status="deleted")]
        out, _ = translate("claude", rows)
        self.assertEqual([r["type"] for r in out], ["session"] + ["plan"] * 9)
        plans = [[(e["content"], e["status"]) for e in r["entries"]] for r in out[1:]]
        done, doing = ("Read the advisories", "completed"), ("Upgrade the seven apps", "in_progress")
        self.assertEqual(plans[:3], [[("Read the advisories", "pending")],
                                     [("Read the advisories", "pending"), ("Upgrade the apps", "pending")],
                                     [("Read the advisories", "in_progress"), ("Upgrade the apps", "pending")]])
        self.assertEqual(plans[3:], [[done, ("Upgrade the apps", "pending")], [done, doing],
                                     [done, doing, ("Refused", "pending")], [done, doing],
                                     [done, doing, ("Spare", "pending")], [done, doing]])

    def turns(self, rows, idle=False):
        """The records of rows, and the result records' stop reasons; idle: a read that finds no new line after them."""
        tr = threads.Translator("claude")
        out = [r for row in rows for r in tr.records(row)]
        if idle:
            out += tr.idle()
        return out, [r["stop_reason"] for r in out if r["type"] == "result"], tr

    def test_a_turn_ends_once_whatever_rows_claude_code_writes_for_it(self):
        """Plan C1: end_turn or turn_duration, one end for each turn. Measured on this Mac: about one end_turn message
        in five has no turn_duration row, and four in ten are two rows of one message (its thinking, then its text)."""
        ask = {"type": "user", "sessionId": SESSION, "message": {"role": "user", "content": "Go."}}
        one = {"type": "assistant", "sessionId": SESSION, "message": {"id": "msg_1", "stop_reason": "end_turn",
                                                                       "content": [{"type": "text", "text": "Done."}]}}
        think = {"type": "assistant", "sessionId": SESSION, "message": {"id": "msg_2", "stop_reason": "end_turn",
                 "content": [{"type": "thinking", "thinking": "All done.", "signature": "s"}]}}
        said = {"type": "assistant", "sessionId": SESSION, "message": {"id": "msg_2", "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "Finished."}]}}
        took = {"type": "system", "subtype": "turn_duration", "sessionId": SESSION}
        hooks = {"type": "system", "subtype": "stop_hook_summary", "sessionId": SESSION}
        # an end_turn message and no turn_duration: one end, once a read finds no new line
        out, ends, tr = self.turns([ask, one])
        self.assertEqual(ends, [])                          # the message may have a second row on its way
        self.assertEqual([r["stop_reason"] for r in tr.idle()], ["end_turn"])
        self.assertEqual(tr.idle(), [])                     # and never twice
        # two rows of one message: one end, after the text; a turn_duration after it is no second end
        out, ends, _ = self.turns([ask, think, said, took])
        self.assertEqual(ends, ["end_turn"])
        self.assertEqual([r["type"] for r in out][-3:], ["agent_thought", "agent_message", "result"])
        out, ends, _ = self.turns([ask, think, said, hooks, took, ask, one, took])
        self.assertEqual(ends, ["end_turn", "end_turn"])     # two turns, two ends
        # a turn_duration alone (a message whose rows carry no stop reason) is the end of its turn
        plain = {"type": "assistant", "sessionId": SESSION, "message": {"id": "msg_3", "content": [{"type": "text", "text": "Ok."}]}}
        self.assertEqual(self.turns([ask, plain, took, took])[1], ["end_turn"])
        # a session that ends with an end pending gives it at its finish
        tr = threads.Translator("claude")
        for row in (ask, one):
            tr.records(row)
        self.assertEqual([r["stop_reason"] for r in tr.finish() if r["type"] == "result"], ["end_turn"])
        # a subagent's own end_turn is no end of the main session
        side = {"type": "assistant", "sessionId": SESSION, "isSidechain": True, "message": dict(one["message"], id="msg_9")}
        self.assertEqual(self.turns([ask, side], idle=True)[1], [])

    def test_a_background_command_stays_open_until_its_own_end_notice(self):
        """Plan C1, with the real shapes of Claude Code 2.1: run_in_background gives backgroundTaskId, a Monitor gives
        taskId, and each ends with a task notice that names its tool-use-id or its task id and a status. A monitor's
        event notices have no status and keep it open."""
        def call(cid, name, command):
            return {"type": "assistant", "sessionId": SESSION, "message": {"id": f"m-{cid}", "content": [
                {"type": "tool_use", "id": cid, "name": name, "input": {"command": command}}]}}

        def result(cid, text, **use):
            return {"type": "user", "sessionId": SESSION, "toolUseResult": use, "message": {"content": [
                {"type": "tool_result", "tool_use_id": cid, "content": text}]}}

        def notice(task, status=None, cid=None, queued=True):
            body = (f"<task-notification>\n<task-id>{task}</task-id>\n" + (f"<tool-use-id>{cid}</tool-use-id>\n" if cid else "")
                    + (f"<status>{status}</status>\n" if status else "<event>line</event>\n") + "</task-notification>")
            return {"type": "queue-operation", "operation": "enqueue", "sessionId": SESSION, "content": body} if queued \
                else {"type": "user", "sessionId": SESSION, "message": {"role": "user", "content": body}}
        rows = [call("toolu_b", "Bash", "npm run build"),
                result("toolu_b", "Command running in background with ID: b1.", backgroundTaskId="b1"),
                call("toolu_m", "Monitor", "tail -f log"),
                result("toolu_m", "Monitor started (task m1).", taskId="m1", timeoutMs=300000),
                call("toolu_f", "Bash", "ls"), result("toolu_f", "a b")]
        out, _, tr = self.turns(rows)
        updates = [r for r in out if r["type"] == "tool_call_update"]
        self.assertEqual([(u["tool_call_id"], u["status"], u.get("background")) for u in updates],
                         [("toolu_b", "in_progress", True), ("toolu_m", "in_progress", True), ("toolu_f", "completed", None)])
        self.assertEqual(tr.open, {"toolu_b", "toolu_m"})
        # a monitor's event keeps it open; the build's end closes it with its status, by its tool-use-id
        more = [r for row in (notice("m1"), notice("b1", "failed", cid="toolu_b")) for r in tr.records(row)]
        self.assertEqual([(r["tool_call_id"], r["status"]) for r in more], [("toolu_b", "failed")])
        self.assertEqual(tr.open, {"toolu_m"})
        # the monitor ends by its task id alone, in a notice that reaches an idle session as its words
        more = [r for r in tr.records(notice("m1", "completed", queued=False))]
        self.assertEqual([(r["tool_call_id"], r["status"]) for r in more if r["type"] == "tool_call_update"],
                         [("toolu_m", "completed")])
        self.assertEqual(tr.open, set())
        # the session ends with a background command open: it did not finish
        out, _, tr = self.turns(rows[:2])
        self.assertEqual([(r["tool_call_id"], r["status"]) for r in tr.finish()], [("toolu_b", "failed")])
        self.assertEqual(tr.open, set())

    def test_a_background_command_that_the_session_stops_ends_at_the_stop(self):
        """Claude Code gives no end notice for a background task that the session stops itself (2.1.321, 11 November
        2026: two of two in one session). The command's call stayed open, and the hub counted a stopped command as
        work at every turn end until the session's end: four commands of three tasks in the fleet's records, each
        with one or two turn ends after its stop. The stop's own result is the command's end."""
        def call(cid, name, **args):
            return {"type": "assistant", "sessionId": SESSION, "message": {"id": f"m-{cid}", "content": [
                {"type": "tool_use", "id": cid, "name": name, "input": args}]}}

        def result(cid, text, error=False, **use):
            return {"type": "user", "sessionId": SESSION, "toolUseResult": use, "message": {"content": [
                {"type": "tool_result", "tool_use_id": cid, "content": text, "is_error": error}]}}
        said = '{"message":"Successfully stopped task: b1 (npm run build)","task_id":"b1","task_type":"local_bash"}'
        rows = [call("toolu_b", "Bash", command="npm run build", run_in_background=True),
                result("toolu_b", "Command running in background with ID: b1.", backgroundTaskId="b1"),
                call("toolu_m", "Monitor", command="tail -f log"),
                result("toolu_m", "Monitor started (task m1).", taskId="m1")]

        def ends(more):
            out, _, tr = self.turns(rows + more)
            return [(r["tool_call_id"], r["status"]) for r in out if r["type"] == "tool_call_update"][2:], tr
        updates, tr = ends([call("toolu_s", "TaskStop", task_id="b1"),
                            result("toolu_s", said, message="Successfully stopped task: b1", task_id="b1")])
        self.assertEqual(updates, [("toolu_b", "failed"), ("toolu_s", "completed")])     # the command, then the stop
        self.assertEqual((tr.open, tr.shells), ({"toolu_m"}, {"toolu_m": "m1"}))
        # a notice of that stop, where a version gives one, ends nothing a second time
        late = {"type": "queue-operation", "operation": "enqueue", "content": "<task-notification>\n<task-id>b1</task-id>\n"
                "<tool-use-id>toolu_b</tool-use-id>\n<status>killed</status>\n</task-notification>"}
        self.assertEqual(tr.records(late), [])
        # a stop that failed, and a stop of another task, end nothing
        updates, tr = ends([call("toolu_s", "TaskStop", task_id="b1"), result("toolu_s", "No task b1", error=True),
                            call("toolu_t", "TaskStop", task_id="b9"), result("toolu_t", said.replace("b1", "b9"))])
        self.assertEqual(updates, [("toolu_s", "failed"), ("toolu_t", "completed")])
        self.assertEqual(tr.open, {"toolu_b", "toolu_m"})
        # the older tool names its task in shell_id, and a monitor stops the same way
        updates, tr = ends([call("toolu_k", "KillShell", shell_id="m1"), result("toolu_k", "Stopped m1")])
        self.assertEqual((updates, tr.open), ([("toolu_m", "failed"), ("toolu_k", "completed")], {"toolu_b"}))

    def test_a_workflow_runs_in_the_background_until_its_own_end_notice(self):
        """AUTONOMY.md decision 41, with the shapes of Claude Code 2.1.308 against a stand-in (28 October 2026): a
        Workflow call's result is async_launched with a taskId, and its end is one task notice with the call's
        tool-use-id, its task id and completed, failed or killed, queued first and then the session's own words. The
        call is background work until then, titled as Claude Code titles it, and its agents' transcripts stay out of
        the records."""
        script = ("export const meta = {\n  name: 'review',\n  description: 'Review the \\'three\\' parts',\n"
                  "  phases: [{ title: 'Read' }]\n}\nconst a = await agent('Read part one', { label: 'one' })\n")

        def call(cid, **args):
            return {"type": "assistant", "sessionId": SESSION, "message": {"id": f"m-{cid}", "content": [
                {"type": "tool_use", "id": cid, "name": "Workflow", "input": args}]}}

        def launched(cid, task, error=False):
            use = {} if error else {"status": "async_launched", "taskId": task, "taskType": "local_workflow",
                                    "workflowName": "review", "runId": "wf_ad53e04e-8f4", "summary": "Review"}
            return {"type": "user", "sessionId": SESSION, "toolUseResult": use, "message": {"content": [
                {"type": "tool_result", "tool_use_id": cid, "is_error": error,
                 "content": "<tool_use_error>No.</tool_use_error>" if error else
                 f"Workflow launched in background. Task ID: {task}\\nSummary: Review"}]}}

        def notice(task, cid, status, queued=True):
            body = (f"<task-notification>\n<task-id>{task}</task-id>\n<tool-use-id>{cid}</tool-use-id>\n"
                    f"<status>{status}</status>\n<summary>Dynamic workflow \"Review\" {status}</summary>\n"
                    f"<usage><agent_count>2</agent_count><subagent_tokens>36</subagent_tokens></usage>\n"
                    "</task-notification>")
            if queued:
                return {"type": "queue-operation", "operation": "enqueue", "sessionId": SESSION, "content": body}
            return {"type": "user", "sessionId": SESSION, "message": {"role": "user", "content": body}}
        rows = [call("toolu_w", script=script), launched("toolu_w", "wyzl38dzo"),
                call("toolu_n", name="nightly-check"), launched("toolu_n", "k2"),
                call("toolu_p", scriptPath="/kit/.claude/workflows/sweep.mjs"), launched("toolu_p", "k3"),
                call("toolu_x", script=script), launched("toolu_x", "", error=True)]
        out, _, tr = self.turns(rows)
        self.assertEqual([r["title"] for r in out if r["type"] == "tool_call"],
                         ["Workflow: Review the \\'three\\' parts", "Workflow: nightly-check", "Workflow: sweep.mjs",
                          "Workflow: Review the \\'three\\' parts"])
        self.assertEqual([(u["tool_call_id"], u["status"], u.get("background")) for u in out
                          if u["type"] == "tool_call_update"],
                         [("toolu_w", "in_progress", True), ("toolu_n", "in_progress", True),
                          ("toolu_p", "in_progress", True), ("toolu_x", "failed", None)])
        self.assertEqual(tr.open, {"toolu_w", "toolu_n", "toolu_p"})
        # its end notice closes it with its status, by its tool-use-id or by its task id; the session's own copy of
        # the same notice changes nothing
        more = [r for row in (notice("wyzl38dzo", "toolu_w", "completed"), notice("wyzl38dzo", "toolu_w", "completed",
                                                                                    queued=False),
                              notice("k2", "", "killed")) for r in tr.records(row)]
        self.assertEqual([(r["tool_call_id"], r["status"]) for r in more if r["type"] == "tool_call_update"],
                         [("toolu_w", "completed"), ("toolu_n", "failed")])
        self.assertEqual(tr.open, {"toolu_p"})
        self.assertNotIn("subagent", json.dumps(out + more))         # no agent's transcript joins the records
        # the session ends with a workflow open: it stopped with it
        self.assertEqual([(r["tool_call_id"], r["status"]) for r in tr.finish() if r["type"] == "tool_call_update"],
                         [("toolu_p", "failed")])
        self.assertEqual(tr.open, set())

    def test_codex_lines_become_acp_records(self):
        out, tr = translate("codex", CODEX)
        self.assertEqual([r["type"] for r in out], [
            "session", "user_message", "agent_thought", "plan", "tool_call", "tool_call", "tool_call", "tool_call_update",
            "agent_message", "error", "result", "tool_call"])
        self.assertEqual(out[1]["text"], "Your task is T-8.")           # the session marker is not shown
        self.assertEqual(out[3]["entries"], [{"content": "Write file", "status": "in_progress"}])
        self.assertEqual((out[4]["tool_call_id"], out[4]["kind"], out[4]["status"]), ("call_1", "execute", "in_progress"))
        self.assertEqual((out[5]["title"], out[5]["status"]), ("Shell: false", "failed"))
        self.assertEqual((out[6]["server"], out[6]["kind"], out[6]["status"]), ("fleet", "other", "completed"))
        self.assertEqual((out[7]["tool_call_id"], out[7]["output"]), ("call_1", "done"))
        self.assertEqual((out[9]["code"], out[9]["resets_at"]), ("usage_limit", 1792154554.0))
        self.assertEqual(tr.open, {"call_2"})

    def test_a_codex_code_mode_plan_is_its_plan(self):
        """Codex 0.163's models call their tools from an exec script, and its rollout has the plan only there: the real
        shape of 4 November 2026 first. A script that only keeps its plan shows as the plan; one that does more shows
        its plan and its call; a plan that is no literal, such as {plan: steps}, leaves the call as it was."""
        real = ('await tools.update_plan({plan:[{step:"Step one",status:"in_progress"},{step:"Step two",'
                'status:"pending"},{step:"Step three",status:"pending"}]});\n')
        rows = [
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "p1", "input": real}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "p1",
                "output": "Script completed\nWall time 0.1 seconds\nOutput:\n"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "p2", "input":
                "text(await tools.update_plan({explanation: 'Step one is done', plan: [\n"
                "  {step: \"Step one\", status: 'completed'}, // the logs\n"
                "  {step: `Fix \\\"the\\\" bug \\u2014 twice`, status: \"in_progress\"},\n"
                "  /* last */ {'step': 'Step three', \"status\": 'pending'},\n]}));"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "p3", "input":
                'await tools.update_plan({plan:[{step:"Step one",status:"completed"}]});\n'
                'text(await tools.exec_command({cmd:"ls"}));'}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "p3", "output": "a b"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "p4",
                "input": "const steps = [];\nawait tools.update_plan({plan: steps});"}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "p5",
                "input": 'await tools.update_plan({plan:[{step:`Run ${name}`,status:"pending"}]});'}},
        ]
        out, tr = translate("codex", rows)
        self.assertEqual([(r["type"], r.get("tool_call_id")) for r in out], [
            ("plan", None), ("plan", None), ("plan", None), ("tool_call", "p3"), ("tool_call_update", "p3"),
            ("tool_call", "p4"), ("tool_call", "p5")])
        self.assertEqual(out[0]["entries"], [{"content": "Step one", "status": "in_progress"},
                                             {"content": "Step two", "status": "pending"},
                                             {"content": "Step three", "status": "pending"}])
        self.assertEqual(out[1]["entries"], [{"content": "Step one", "status": "completed"},
                                             {"content": 'Fix "the" bug — twice', "status": "in_progress"},
                                             {"content": "Step three", "status": "pending"}])
        self.assertEqual(out[2]["entries"], [{"content": "Step one", "status": "completed"}])
        self.assertEqual((out[3]["kind"], out[4]["output"]), ("execute", "a b"))
        self.assertEqual(tr.open, {"p4", "p5"})

    def test_a_codex_background_command_stays_one_open_call_named_by_its_command(self):
        """Real T-66 shapes (Codex 0.160): the command outlives its exec script, a poll waits on it, the turn is
        aborted, and the process end comes later as a CommandExecution with the same process_id."""
        start = ('text(await tools.exec_command({cmd:\'sleep 90 && curl -s -X POST "$FLEET_HUB/outbox" -d key=k -d text=A\','
                 'yield_time_ms:1000,max_output_tokens:1000}));')
        rows = [
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c1", "input": start}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c1", "output": [
                {"type": "input_text", "text": "Script completed\nWall time 1.2 seconds\nOutput:\n"},
                {"type": "input_text", "text": json.dumps({"chunk_id": "bc79cc", "wall_time_seconds": 1.0, "session_id": 94316})}]}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c2",
                "input": 'text(await tools.write_stdin({session_id:94316,chars:"",yield_time_ms:50000,max_output_tokens:1000}));'}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c2", "output": "aborted by user after 23.9s"}},
            {"type": "event_msg", "payload": {"type": "turn_aborted", "reason": "interrupted"}},
            {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "CommandExecution", "id": "exec-9727",
                "process_id": "94316", "command": ["/bin/bash", "-lc", "sleep 90 && curl"], "status": "completed", "exit_code": 0,
                "aggregated_output": '{"ok": true, "count": 1}'}}},
        ]
        out, tr = translate("codex", rows)
        self.assertEqual([(r["type"], r.get("tool_call_id"), r.get("kind"), r.get("status")) for r in out], [
            ("tool_call", "c1", "execute", "in_progress"), ("tool_call_update", "c1", None, "completed"),
            ("tool_call", "proc-94316", "execute", "in_progress"),
            ("tool_call", "c2", "read", "in_progress"), ("tool_call_update", "c2", None, "completed"),
            ("result", None, None, None), ("tool_call_update", "proc-94316", None, "completed")])
        self.assertEqual(out[2]["title"], 'Shell (background): sleep 90 && curl -s -X POST "$FLEET_HUB/outbox" -d key=k -d text=A')
        self.assertEqual(out[3]["title"], "Wait: background session 94316")
        self.assertTrue(out[4]["interrupted"])
        self.assertEqual(out[6]["output"], '{"ok": true, "count": 1}')
        self.assertEqual(tr.open, set())
        # a command that finished inside its wait, input sent to a process, and an output the script order cannot match
        rows = [
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c3",
                "input": 'text(await tools.exec_command({cmd:"ls"})); text(await tools.exec_command({cmd:"sleep 300"}));'}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c3", "output": [
                {"type": "input_text", "text": json.dumps({"chunk_id": "a", "exit_code": 0, "output": "x"})}]}},
            {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c4",
                "input": 'text(await tools.write_stdin({session_id:777,chars:"yes\\n"}));'}},
            {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c4", "output": [
                {"type": "input_text", "text": json.dumps({"chunk_id": "b", "session_id": 778})},
                {"type": "input_text", "text": json.dumps({"chunk_id": "c", "session_id": 779})}]}},
        ]
        out, tr = translate("codex", rows)
        self.assertEqual([r.get("tool_call_id") for r in out if r["type"] == "tool_call"], ["c3", "c4", "proc-778", "proc-779"])
        self.assertEqual(next(r for r in out if r.get("tool_call_id") == "c4")["kind"], "execute")   # it types into a process
        self.assertEqual(next(r for r in out if r.get("tool_call_id") == "proc-778")["title"], "Shell (background): background session 778")

    def test_codex_limit_is_reported_again_only_after_it_cleared(self):
        clear = CODEX[10]
        hit = CODEX[11]
        out, _ = translate("codex", [hit, hit, clear, hit])
        self.assertEqual([r["code"] for r in out], ["usage_limit", "usage_limit"])

    def test_codex_usage_limit_error_event(self):
        out, _ = translate("codex", [CODEX[10], {"type": "event_msg", "payload": {"type": "error",
            "message": "You've hit your usage limit. Try again later.", "codex_error_info": "usage_limit_exceeded"}}])
        self.assertEqual((out[0]["code"], out[0]["resets_at"]), ("usage_limit", 1792154554.0))

    def test_a_codex_turn_that_its_error_ended_is_no_normal_end(self):
        """Newer rollouts give the error that ended a turn, such as its usage limit, only in its task_complete."""
        out, _ = translate("codex", [CODEX[10], {"type": "event_msg", "payload": {
            "type": "task_complete", "turn_id": "t1", "last_agent_message": None,
            "error": {"message": "Your workspace is out of credits.", "codex_error_info": "usage_limit_exceeded"}}}])
        self.assertEqual([(r["type"], r.get("code"), r.get("stop_reason")) for r in out],
                         [("error", "usage_limit", None), ("result", None, "error")])
        self.assertEqual(out[0]["resets_at"], 1792154554.0)
        out, _ = translate("codex", [{"type": "event_msg", "payload": {"type": "task_complete", "turn_id": "t2",
            "error": {"message": "stream disconnected", "codex_error_info": "response_stream_disconnected"}}}])
        self.assertEqual([(r["type"], r.get("code"), r.get("stop_reason")) for r in out],
                         [("error", "response_stream_disconnected", None), ("result", None, "error")])
        out, _ = translate("codex", [{"type": "event_msg", "payload": {"type": "task_complete", "error": None}}])
        self.assertEqual([(r["type"], r["stop_reason"]) for r in out], [("result", "end_turn")])

    def test_a_codex_usage_limit_that_a_token_count_gave_is_given_once(self):
        limited_end = {"type": "event_msg", "payload": {"type": "task_complete", "turn_id": "t1", "error": {
            "message": "You've hit your usage limit.", "codex_error_info": "usage_limit_exceeded"}}}
        out, _ = translate("codex", [CODEX[11], limited_end])
        self.assertEqual([(r["type"], r.get("code"), r.get("stop_reason")) for r in out],
                         [("error", "usage_limit", None), ("result", None, "error")])
        out, _ = translate("codex", [CODEX[11], CODEX[10], limited_end])     # it cleared, then came again
        self.assertEqual([r.get("code") for r in out if r["type"] == "error"], ["usage_limit", "usage_limit"])

    def test_a_codex_usage_limit_in_a_later_turn_gives_its_own_record(self):
        """The hub holds a task at its limit only on a limit record of that turn: without one, a turn that ended with
        an error would pause the task as failed."""
        limited_end = {"type": "event_msg", "payload": {"type": "task_complete", "error": {
            "message": "You've hit your usage limit.", "codex_error_info": "usage_limit_exceeded"}}}
        turn = lambda n: {"type": "event_msg", "payload": {"type": "task_started", "turn_id": f"t{n}"}}
        out, _ = translate("codex", [turn(1), CODEX[11], limited_end, turn(2), limited_end])
        self.assertEqual([(r["type"], r.get("code"), r.get("stop_reason")) for r in out],
                         [("error", "usage_limit", None), ("result", None, "error"),
                          ("error", "usage_limit", None), ("result", None, "error")])

    def test_codex_app_notifications_become_acp_records(self):
        """A screen task's record file (Codex app-server v2 shapes): each started call is open until its item completes."""
        out, tr = translate("codex_app", APP)
        self.assertEqual([r["seq"] for r in out], list(range(1, len(out) + 1)))
        self.assertEqual([(r["type"], r.get("tool_call_id"), r.get("status")) for r in out], [
            ("session", None, None), ("user_message", None, None), ("agent_thought", None, None), ("plan", None, None),
            ("tool_call", "call_f1", "in_progress"), ("tool_call_update", "call_f1", "completed"),
            ("tool_call", "call_c1", "in_progress"), ("tool_call_update", "call_c1", "completed"),
            ("tool_call", "call_s1", "in_progress"), ("tool_call_update", "call_s1", "failed"),
            ("tool_call", "call_e1", "completed"), ("agent_message", None, None), ("result", None, None),
            ("tool_call", "call_c2", "in_progress")])
        self.assertEqual((out[0]["runtime"], out[0]["session_id"], out[0]["ts"]), ("codex", "thr-1", 1791640000.0))
        self.assertEqual((out[1]["text"], out[2]["text"]), ("Your task is T-9.", "Open Calculator first"))
        self.assertEqual(out[3]["entries"], [{"content": "Open Calculator", "status": "completed"},
                                             {"content": "Compute 63 × 2", "status": "in_progress"}])
        self.assertEqual((out[4]["title"], out[4]["kind"], out[4]["server"]), ("fleet: report_progress: T-9", "other", "fleet"))
        self.assertEqual(out[5]["output"], "Noted.")
        # cua_repl's readOnlyHint is ignored: a click is an effect, so a stop while it runs is an unknown outcome
        self.assertEqual((out[6]["title"], out[6]["kind"], out[6]["server"]), ("cua_repl: js: await app.click(5);", "other", "cua_repl"))
        self.assertEqual(out[7]["output"], "clicked")
        self.assertEqual((out[8]["title"], out[8]["kind"]), ("Shell: ls outputs/T-9/computer-use", "execute"))
        self.assertEqual(out[9]["output"], "ls: No such file or directory")
        self.assertEqual((out[10]["title"], out[10]["kind"]), ("Edit: /kit/outputs/T-9/notes.md", "edit"))
        self.assertEqual((out[10]["changes"], out[10]["locations"]), ([{"path": "/kit/outputs/T-9/notes.md", "action": "add",
                                                                        "added": 1, "removed": 0}], [{"path": "/kit/outputs/T-9/notes.md"}]))
        self.assertEqual((out[11]["text"], out[12]["stop_reason"]), ("126 is on the screen.", "end_turn"))
        self.assertEqual(tr.open, {"call_c2"})
        again, _ = translate("codex_app", APP)
        self.assertEqual(again, out)

    def test_codex_app_errors_results_and_usage_limits(self):
        limits = lambda percent, reached=None: app("account/rateLimits/updated", rateLimits={
            "limitId": "codex", "limitName": None, "primary": {"usedPercent": percent, "windowDurationMins": 300,
            "resetsAt": 1792154554}, "secondary": None, "credits": None, "rateLimitReachedType": reached})
        sparse = app("account/rateLimits/updated", rateLimits={"limitId": "codex", "primary": None, "secondary": None,
                                                               "rateLimitReachedType": None})
        failed = lambda turn, error: app("turn/completed", threadId="thr-1", turn={"id": turn, "status": "failed", "error": error})
        usage = {"message": "You've hit your usage limit.", "codexErrorInfo": "usageLimitExceeded", "additionalDetails": None}
        out, _ = translate("codex_app", [
            limits(40), limits(100, "rate_limit_reached"), limits(100, "rate_limit_reached"), sparse, limits(10), limits(100),
            app("error", threadId="thr-1", turnId="turn-2", willRetry=True,
                error={"message": "Reconnecting... 1/5", "codexErrorInfo": {"responseStreamDisconnected": {"httpStatusCode": None}}}),
            app("error", threadId="thr-1", turnId="turn-2", willRetry=False, error=usage),
            failed("turn-2", usage),
            failed("turn-3", {"message": "Bad request", "codexErrorInfo": {"httpConnectionFailed": {"httpStatusCode": 400}}}),
            app("turn/completed", threadId="thr-1", turn={"id": "turn-4", "status": "interrupted", "error": None}),
        ])
        self.assertEqual([(r["type"], r.get("code") or r.get("stop_reason")) for r in out], [
            ("error", "usage_limit"), ("error", "usage_limit"),         # once per stretch; a sparse update changes nothing
            ("session", None), ("error", "usage_limit"), ("result", "error"),     # the turn's error is one record
            ("error", "http_connection_failed"), ("result", "error"), ("result", "cancelled")])
        self.assertEqual({r["resets_at"] for r in out if r.get("code") == "usage_limit"}, {1792154554.0})
        self.assertEqual((out[3]["message"], out[3]["retryable"]), ("You've hit your usage limit.", True))
        self.assertEqual((out[5]["resets_at"], out[5]["retryable"]), (None, False))

    def test_codex_app_file_changes_have_counts_only_from_a_whole_diff(self):
        diff = "@@ -1,2 +1,3 @@\n-old\n+new\n+more\n same"
        item = {"type": "fileChange", "id": "call_e2", "status": "inProgress", "changes": [
            {"path": "/kit/outputs/T-9/b.md", "kind": {"type": "update", "move_path": None}, "diff": diff},
            {"path": "/kit/outputs/T-9/a.md", "kind": {"type": "update", "move_path": "/kit/outputs/T-9/c.md"},
             "diff": "+x\n" * 2000 + "…"},                       # clipped by the runner: no counts
            {"path": "/tmp/gone.txt", "kind": {"type": "delete"}, "diff": "one\ntwo\n"}]}
        tr = threads.Translator("codex_app", root="/kit")
        out = tr.records(app_item("item/started", item)) + tr.records(app_item("item/completed", dict(item, status="completed")))
        self.assertEqual([(r["type"], r.get("status")) for r in out], [("session", None), ("tool_call", "in_progress"),
                                                                        ("tool_call_update", "completed")])
        self.assertEqual(out[1]["changes"], [                  # in the order of the paths as written, like rollouts
            {"path": "outputs/T-9/a.md", "action": "move", "added": None, "removed": None},
            {"path": "outputs/T-9/b.md", "action": "modify", "added": 2, "removed": 1},
            {"path": "/tmp/gone.txt", "action": "delete", "added": 0, "removed": 2}])
        self.assertEqual(out[1]["title"], "Edit: /kit/outputs/T-9/a.md, /kit/outputs/T-9/b.md, /tmp/gone.txt")
        self.assertNotIn("+new", json.dumps(out))

    def test_odd_codex_app_lines_do_not_stop_the_translation(self):
        """A translator exception would make the feed read the same lines again with new numbers."""
        rows = [app("item/completed"), app("item/started", item={"type": "commandExecution"}),
                app_item("item/completed", {"type": "reasoning", "id": "r", "summary": 5}),
                app_item("item/completed", {"type": "fileChange", "id": "f", "changes": {"a": 1}, "status": None}),
                app("turn/plan/updated", threadId="thr-1", plan="x"), app("turn/completed", turn=[]),
                app("account/rateLimits/updated", rateLimits=[]), {"method": "error", "params": None}]
        out, _ = translate("codex_app", rows)
        self.assertEqual([(r["type"], r.get("title") or r.get("code")) for r in out],
                         [("session", None), ("tool_call", "Edit: "), ("plan", None), ("error", "error")])

    def test_translation_is_deterministic_and_bounded(self):
        big = dict(CLAUDE[3], message={"content": [{"type": "text", "text": "x" * 50000}]})
        first, _ = translate("claude", CLAUDE + [big])
        second, _ = translate("claude", CLAUDE + [big])
        self.assertEqual(first, second)
        self.assertEqual(len(first[-1]["text"]), threads.TEXT)
        self.assertTrue(all(len(json.dumps(r)) < threads.BATCH_BYTES for r in first))


def claude_use(call, name, args, sidechain=False):
    return {"type": "assistant", "sessionId": SESSION, "isSidechain": sidechain,
            "message": {"content": [{"type": "tool_use", "id": call, "name": name, "input": args}]}}


def claude_result(call, text="ok", result=None, sidechain=False):
    row = {"type": "user", "sessionId": SESSION, "isSidechain": sidechain,
           "message": {"content": [{"type": "tool_result", "tool_use_id": call, "content": text}]}}
    if result is not None:
        row["toolUseResult"] = result
    return row


class FilesAndSubagents(unittest.TestCase):
    """Owner API 1.4: file-change rows and subagent rows, from real-format Claude Code and Codex lines."""

    def test_claude_edit_tools_give_locations_and_changes_without_text(self):
        kit = "/kit"
        tr = threads.Translator("claude", root=kit)
        rows = [claude_use("r1", "Read", {"file_path": "/kit/a.txt"}),
                claude_use("w1", "Write", {"file_path": "/kit/a.txt", "content": "x\ny\n"}),
                claude_use("w2", "Write", {"file_path": "/kit/new.md", "content": "one line"}),
                claude_use("e1", "Edit", {"file_path": "/kit/b.py", "old_string": "a\nb", "new_string": "a\nb\nc", "replace_all": False}),
                claude_use("e2", "Edit", {"file_path": "/kit/b.py", "old_string": "x", "new_string": "y", "replace_all": True}),
                claude_use("m1", "MultiEdit", {"file_path": "/elsewhere/c.py", "edits": [
                    {"old_string": "a", "new_string": "b\nc"}, {"old_string": "d\ne", "new_string": "f"}]}),
                claude_use("g1", "Grep", {"pattern": "TODO", "path": "/kit/src"}),
                claude_use("w3", "Write", {"file_path": "/kit/new.md", "content": "two\nlines"})]
        out = [r for row in rows for r in tr.records(row)]
        by = {r["tool_call_id"]: r for r in out if r["type"] == "tool_call"}
        self.assertEqual(by["r1"]["locations"], [{"path": "a.txt"}])
        self.assertNotIn("changes", by["r1"])
        self.assertEqual(by["w1"]["changes"], [{"path": "a.txt", "action": "modify", "added": 2, "removed": None}])
        self.assertEqual(by["w2"]["changes"], [{"path": "new.md", "action": "add", "added": 1, "removed": None}])
        self.assertEqual(by["e1"]["changes"], [{"path": "b.py", "action": "modify", "added": 3, "removed": 2}])
        self.assertEqual(by["e2"]["changes"], [{"path": "b.py", "action": "modify", "added": None, "removed": None}])
        self.assertEqual(by["m1"]["changes"], [{"path": "/elsewhere/c.py", "action": "modify", "added": 3, "removed": 3}])
        self.assertEqual(by["g1"]["locations"], [{"path": "src"}])
        self.assertEqual(by["w3"]["changes"], [{"path": "new.md", "action": "modify", "added": 2, "removed": None}])  # it wrote it before
        self.assertNotIn("x\ny", json.dumps(out))         # no file text

    def subagent_rows(self):
        child_a1 = [claude_use("x1", "Bash", {"command": "rm -f tmp.txt"}, True),
                    claude_result("x1", "removed", sidechain=True),
                    claude_use("n1", "Agent", {"description": "Nested check", "subagent_type": "Explore"}, True),
                    claude_result("n1", "nested done", {"status": "completed", "agentId": "a3"}, True),
                    {"type": "assistant", "sessionId": SESSION, "isSidechain": True,
                     "message": {"content": [{"type": "text", "text": "Child finished."}]}}]
        child_a3 = [claude_use("g1", "Read", {"file_path": "/kit/n.txt"}, True), claude_result("g1", "text", sidechain=True)]
        child_a2 = [claude_use("y1", "Edit", {"file_path": "/kit/z.txt", "old_string": "a", "new_string": "b"}, True)]
        files = {"a1": child_a1, "a2": child_a2, "a3": child_a3}
        notice = ("<task-notification> <task-id>a2</task-id> <tool-use-id>toolu_B</tool-use-id> "
                  "<status>completed</status> <summary>Agent finished</summary></task-notification>")
        parent = [{"type": "user", "sessionId": SESSION, "message": {"content": "Your task is T-9."}},
                  claude_use("toolu_A", "Agent", {"description": "Check the logs", "subagent_type": "general-purpose", "prompt": "p"}),
                  claude_result("toolu_A", "summary", {"status": "completed", "agentId": "a1"}),
                  claude_use("toolu_B", "Agent", {"description": "Background review", "prompt": "q"}),
                  claude_result("toolu_B", "launched", {"status": "async_launched", "isAsync": True, "agentId": "a2"}),
                  {"type": "assistant", "sessionId": SESSION, "message": {"content": [{"type": "text", "text": "Waiting."}]}},
                  {"type": "queue-operation", "operation": "enqueue", "content": notice},
                  {"type": "queue-operation", "operation": "remove", "content": notice},
                  claude_use("toolu_D", "Agent", {"description": "Old notice form", "prompt": "s"}),
                  claude_result("toolu_D", "launched", {"status": "async_launched", "agentId": "a5"}),
                  {"type": "attachment", "attachment": {"type": "queued_command", "commandMode": "task-notification",
                   "prompt": "<task-notification>\n<task-id>a5</task-id>\n<status>completed</status>\n</task-notification>"}},
                  claude_use("toolu_E", "Agent", {"description": "Stopped one", "prompt": "t"}),
                  claude_result("toolu_E", "launched", {"status": "async_launched", "agentId": "a6"}),
                  {"type": "user", "sessionId": SESSION, "origin": {"kind": "task-notification"}, "message": {"role": "user", "content":
                   "<task-notification>\n<task-id>a6</task-id>\n<tool-use-id>toolu_E</tool-use-id>\n<status>killed</status>\n</task-notification>"}},
                  claude_use("toolu_C", "Agent", {"description": "Never ends", "prompt": "r"}),
                  claude_result("toolu_C", "launched", {"status": "async_launched", "agentId": "a4"}),
                  claude_use("toolu_F", "Agent", {"description": "One of two", "prompt": "u"}),
                  claude_result("toolu_F", "launched", {"status": "async_launched", "agentId": "a7"}),
                  claude_use("toolu_G", "Agent", {"description": "Two of two", "prompt": "v"}),
                  claude_result("toolu_G", "launched", {"status": "async_launched", "agentId": "a8"}),
                  {"type": "queue-operation", "operation": "enqueue", "content":
                   "<task-notification><task-id>a8</task-id><task-id>a7</task-id><status>stopped</status></task-notification>"}]
        files["a4"] = [claude_use("q1", "Bash", {"command": "sleep 60"}, True)]
        files["a5"] = [claude_use("d1", "Glob", {"pattern": "*.md"}, True)]
        files["a6"] = [claude_use("e1", "WebFetch", {"url": "https://example.com"}, True)]
        return parent, files

    def translate_all(self):
        parent, files = self.subagent_rows()
        tr = threads.Translator("claude", root="/kit", children=lambda agent, call=None: files.get(agent))
        out = [r for row in parent for r in tr.records(row)]
        return out + tr.finish()

    def test_claude_subagents_nest_under_their_starting_call_in_one_sequence(self):
        out = self.translate_all()
        self.assertEqual([r["seq"] for r in out], list(range(1, len(out) + 1)))
        self.assertEqual(out, self.translate_all())        # the same files always give the same records
        rows = [(r["type"], r.get("tool_call_id"), r.get("parent"), r.get("status")) for r in out if r["type"] != "session"]
        self.assertEqual(rows, [
            ("user_message", None, None, None),
            ("tool_call", "toolu_A", None, "in_progress"),
            ("tool_call", "toolu_A/x1", "toolu_A", "in_progress"),
            ("tool_call_update", "toolu_A/x1", "toolu_A", "completed"),
            ("tool_call", "toolu_A/n1", "toolu_A", "in_progress"),
            ("tool_call", "toolu_A/n1/g1", "toolu_A/n1", "in_progress"),
            ("tool_call_update", "toolu_A/n1/g1", "toolu_A/n1", "completed"),
            ("tool_call_update", "toolu_A/n1", "toolu_A", "completed"),
            ("agent_message", None, "toolu_A", None),
            ("tool_call_update", "toolu_A", None, "completed"),
            ("tool_call", "toolu_B", None, "in_progress"),
            ("tool_call_update", "toolu_B", None, "in_progress"),    # launched: background work until its notice
            ("agent_message", None, None, None),
            ("tool_call", "toolu_B/y1", "toolu_B", "in_progress"),
            ("tool_call_update", "toolu_B", None, "completed"),
            ("tool_call", "toolu_D", None, "in_progress"),
            ("tool_call_update", "toolu_D", None, "in_progress"),
            ("tool_call", "toolu_D/d1", "toolu_D", "in_progress"),
            ("tool_call_update", "toolu_D", None, "completed"),      # a notice that names only the agent
            ("tool_call", "toolu_E", None, "in_progress"),
            ("tool_call_update", "toolu_E", None, "in_progress"),
            ("tool_call", "toolu_E/e1", "toolu_E", "in_progress"),
            ("tool_call_update", "toolu_E", None, "failed"),         # the notice row is not a user message
            ("tool_call", "toolu_C", None, "in_progress"),
            ("tool_call_update", "toolu_C", None, "in_progress"),
            ("tool_call", "toolu_F", None, "in_progress"),
            ("tool_call_update", "toolu_F", None, "in_progress"),
            ("tool_call", "toolu_G", None, "in_progress"),
            ("tool_call_update", "toolu_G", None, "in_progress"),
            ("tool_call_update", "toolu_F", None, "failed"),         # one older notice for two agents
            ("tool_call_update", "toolu_G", None, "failed"),
            ("tool_call", "toolu_C/q1", "toolu_C", "in_progress")])  # no end: shown at the session's end
        by = {r.get("tool_call_id"): r for r in out if r["type"] == "tool_call"}
        self.assertEqual(by["toolu_A"]["subagent"], {"name": "general-purpose"})
        self.assertEqual(by["toolu_B"]["subagent"], {"name": "Background review"})
        self.assertEqual(by["toolu_A/n1"]["subagent"], {"name": "Explore"})
        self.assertEqual(by["toolu_B/y1"]["changes"], [{"path": "z.txt", "action": "modify", "added": 1, "removed": 1}])
        self.assertEqual(by["toolu_A"]["kind"], "other")

    def test_codex_file_change_items_give_changes_and_locations(self):
        tr = threads.Translator("codex", root="/home/claude/fleet-pilot")
        item = {"type": "FileChange", "id": "f1", "status": "completed", "changes": {
            "/home/claude/fleet-pilot/outputs/new.txt": {"type": "add", "content": "a\nb\nc\n"},
            "/home/claude/fleet-pilot/hub.py": {"type": "update", "unified_diff": "--- a\n+++ b\n@@ -1 +1,2 @@\n-x\n+y\n+z\n"},
            "/home/claude/fleet-pilot/old.txt": {"type": "delete", "content": "q\n"},
            "/tmp/moved.txt": {"type": "update", "move_path": "/tmp/new-name.txt", "unified_diff": ""}}}
        out = tr.records({"type": "event_msg", "payload": {"type": "item_completed", "item": item}})
        self.assertEqual(out[0]["changes"], [          # in the order of the paths as Codex wrote them
            {"path": "hub.py", "action": "modify", "added": 2, "removed": 1},
            {"path": "old.txt", "action": "delete", "added": 0, "removed": 1},
            {"path": "outputs/new.txt", "action": "add", "added": 3, "removed": 0},
            {"path": "/tmp/moved.txt", "action": "move", "added": None, "removed": None}])
        self.assertEqual([l["path"] for l in out[0]["locations"]], ["hub.py", "old.txt", "outputs/new.txt", "/tmp/moved.txt"])
        self.assertNotIn("+y", json.dumps(out))

    def test_subagent_files_are_read_only_by_a_safe_agent_id(self):
        with tempfile.TemporaryDirectory() as home:
            parent = os.path.join(home, SESSION + ".jsonl")
            folder = os.path.join(home, SESSION, "subagents")
            os.makedirs(folder)
            with open(os.path.join(folder, "agent-a1.jsonl"), "w") as f:
                f.write(json.dumps({"type": "user"}) + "\n" + '{"type": "assist')
            read = threads.subagent_reader(parent)
            self.assertEqual(read("a1"), [{"type": "user"}])        # the unfinished last line is left out
            self.assertIsNone(read("../a1"))
            self.assertIsNone(read("missing"))
            self.assertIsNone(read(None, "toolu_I"))

    def test_an_interrupted_subagent_is_found_by_its_meta_file(self):
        """A Pause during a subagent: its result has no agent id, but its meta file names the starting call."""
        with tempfile.TemporaryDirectory() as home:
            parent = os.path.join(home, SESSION + ".jsonl")
            folder = os.path.join(home, SESSION, "subagents")
            os.makedirs(folder)
            with open(os.path.join(folder, "agent-a9.meta.json"), "w") as f:
                json.dump({"agentType": "general-purpose", "description": "Send it", "toolUseId": "toolu_I"}, f)
            with open(os.path.join(folder, "agent-a9.jsonl"), "w") as f:
                f.write(json.dumps(claude_use("x9", "Bash", {"command": "curl -X POST outbox"}, True)) + "\n")
            tr = threads.Translator("claude", root="/kit", children=threads.subagent_reader(parent))
            rows = [claude_use("toolu_I", "Agent", {"description": "Send it", "subagent_type": "general-purpose", "prompt": "p"}),
                    claude_result("toolu_I", "[Request interrupted by user for tool use]",
                                  "Error: [Request interrupted by user for tool use]")]
            rows[1]["message"]["content"][0]["is_error"] = True
            out = [r for row in rows for r in tr.records(row) if r["type"] != "session"]
            self.assertEqual([(r["type"], r["tool_call_id"], r.get("status"), r.get("interrupted")) for r in out], [
                ("tool_call", "toolu_I", "in_progress", None),
                ("tool_call", "toolu_I/x9", "in_progress", None),          # the command it was running stays open
                ("tool_call_update", "toolu_I", "failed", True)])

    def subagent_files(self, home, files):
        """The subagent files of a parent transcript: {agent id: (the call that its meta file names, its rows)}."""
        folder = os.path.join(home, SESSION, "subagents")
        os.makedirs(folder)
        for agent, (call, rows) in files.items():
            with open(os.path.join(folder, f"agent-{agent}.meta.json"), "w") as f:
                json.dump({"agentType": "fork", "isFork": True, "toolUseId": call, "spawnDepth": 1}, f)
            with open(os.path.join(folder, f"agent-{agent}.jsonl"), "w") as f:
                f.write("".join(json.dumps(row) + "\n" for row in rows))
        return threads.subagent_reader(os.path.join(home, SESSION + ".jsonl"))

    def test_a_fork_shows_its_own_rows_and_its_end_is_seen(self):
        """A fork's file as Claude Code 2.1.311 and 2.1.321 write it (11 November 2026): a reference to the parent's
        context, a copy of the parent's message that started the fork with each call of it under its own id, one user
        row with a stand-in result for each of those calls and the fork's instructions, then the fork's own rows. Its
        meta file names the starting call. The reader took the copied starting call for a subagent call of the fork,
        found the fork's own file for it and read it inside itself without an end: the fork's end notice was lost
        with that error, and the hub held the call for one that still ran (two tasks of 9 November 2026). Here one
        message of the parent starts two forks and runs a command, so each fork's file has a copy of all three."""
        def start(n):
            return {"description": f"List the keys, part {n}", "subagent_type": "fork", "prompt": f"List part {n}."}

        def fork(agent, call, n):
            stand_in = {call: "Fork started — that fork is you."}
            theirs = "This is the parent's call, not yours. It may not have run yet, and its result goes to the parent."
            words = ("<fork-boilerplate>\nYou are a worker fork. The transcript above is the parent's history. Execute "
                     f"ONE directive, then stop.\n</fork-boilerplate>\n\nYour directive: List part {n}.")
            return [{"type": "fork-context-ref", "agentId": agent, "parentSessionId": SESSION, "contextLength": 96},
                    {"type": "assistant", "sessionId": SESSION, "isSidechain": True, "agentId": agent,
                     "message": {"content": [{"type": "text", "text": "Two forks list the keys while I close the cases."}]}},
                    claude_use("toolu_F", "Agent", start(1), True), claude_use("toolu_G", "Agent", start(2), True),
                    claude_use("toolu_P", "Bash", {"command": "git status"}, True),
                    {"type": "user", "sessionId": SESSION, "isSidechain": True, "agentId": agent, "message": {"content": [
                        {"type": "tool_result", "tool_use_id": c, "content": [{"type": "text", "text": stand_in.get(c, theirs)}]}
                        for c in ("toolu_F", "toolu_G", "toolu_P")] + [{"type": "text", "text": words}]}},
                    claude_use(f"k{n}", "mcp__fleet__see_responsibilities", {"responsibility": "R-6"}, True),
                    claude_result(f"k{n}", "R-6 [active] Vulnerabilities", sidechain=True),
                    {"type": "assistant", "sessionId": SESSION, "isSidechain": True,
                     "message": {"content": [{"type": "text", "text": f"The open keys of part {n}: cve/{n}."}]}}]

        def notice(agent, call):
            return ("<task-notification>\n<task-id>" + agent + "</task-id>\n<tool-use-id>" + call + "</tool-use-id>\n"
                    "<status>completed</status>\n<summary>Agent finished</summary>\n</task-notification>")
        launched = [claude_use("toolu_F", "Agent", start(1)), claude_use("toolu_G", "Agent", start(2)),
                    claude_use("toolu_P", "Bash", {"command": "git status"}),
                    claude_result("toolu_F", "Async agent launched successfully.",
                                  {"isAsync": True, "status": "async_launched", "agentId": "f1"}),
                    claude_result("toolu_G", "Async agent launched successfully.",
                                  {"isAsync": True, "status": "async_launched", "agentId": "f2"}),
                    claude_result("toolu_P", "nothing to commit")]
        ended = [{"type": "queue-operation", "operation": "enqueue", "content": notice("f1", "toolu_F")},
                 {"type": "queue-operation", "operation": "remove", "content": notice("f1", "toolu_F")},
                 {"type": "attachment", "attachment": {"type": "queued_command", "prompt": notice("f1", "toolu_F")}},
                 {"type": "queue-operation", "operation": "enqueue", "content": notice("f2", "toolu_G")}]
        files = {"f1": ("toolu_F", fork("f1", "toolu_F", 1)), "f2": ("toolu_G", fork("f2", "toolu_G", 2))}

        def shape(records):
            return [(r["type"], r.get("tool_call_id"), r.get("parent"), r.get("status")) for r in records
                    if r["type"] != "session"]

        def own(call, n):       # what one fork shows under its call: its instructions, its own call and its answer
            return [("user_message", None, call, None), ("tool_call", f"{call}/k{n}", call, "in_progress"),
                    ("tool_call_update", f"{call}/k{n}", call, "completed"), ("agent_message", None, call, None)]
        with tempfile.TemporaryDirectory() as home:
            children = self.subagent_files(home, files)
            tr = threads.Translator("claude", root="/kit", children=children)
            out = [r for row in launched + ended for r in tr.records(row)]
            late = threads.Translator("claude", root="/kit", children=children)     # its session ends with no notice
            left = [r for row in launched for r in late.records(row)][-3:] + late.finish()
        self.assertEqual(shape(out), [
            ("tool_call", "toolu_F", None, "in_progress"), ("tool_call", "toolu_G", None, "in_progress"),
            ("tool_call", "toolu_P", None, "in_progress"),
            ("tool_call_update", "toolu_F", None, "in_progress"),       # launched: background work until its notice
            ("tool_call_update", "toolu_G", None, "in_progress"),
            ("tool_call_update", "toolu_P", None, "completed")]
            + own("toolu_F", 1) + [("tool_call_update", "toolu_F", None, "completed")]     # one end, from the first notice
            + own("toolu_G", 2) + [("tool_call_update", "toolu_G", None, "completed")])
        said = [r["text"] for r in out if r["type"] in ("user_message", "agent_message")]
        self.assertEqual(said, ["Your directive: List part 1.", "The open keys of part 1: cve/1.",     # not Claude Code's block
                                "Your directive: List part 2.", "The open keys of part 2: cve/2."])
        self.assertEqual(next(r for r in out if r.get("tool_call_id") == "toolu_F")["subagent"], {"name": "fork"})
        self.assertEqual((tr.pending, tr.open & {"toolu_F", "toolu_G"}), ({}, set()))
        # A session that ends before the notices shows each fork as far as it got, and no end that it did not see.
        self.assertEqual(shape(left)[3:], own("toolu_F", 1) + own("toolu_G", 2))
        # The edges of own_rows: instructions with no end of Claude Code's block show no words; a fork's file whose
        # instructions are not written yet has no row of its own; one without the block is its own after its first
        # user row; and every other subagent's file is its own whole.
        rows = files["f1"][1]
        cut = {"type": "user", "message": {"content": "<fork-boilerplate>\nYou are a worker fork."}}
        self.assertEqual(threads.own_rows(rows[:5] + [cut] + rows[6:7]), [{"type": "user", "message": {"content": ""}}, rows[6]])
        self.assertEqual(threads.own_rows(rows[:5]), [])
        plain = dict(rows[5], message={"content": rows[5]["message"]["content"][:3]})
        self.assertEqual(threads.own_rows(rows[:5] + [plain] + rows[6:]), rows[6:])
        whole = rows[6:]
        self.assertIs(threads.own_rows(whole), whole)

    def test_a_subagent_is_never_read_inside_itself(self):
        """Two subagent files in a shape that own_rows does not know: each has a copy of its own starting call and of
        the other's, with results that name no agent, and each meta file names its call. A call that started the
        subagent, or one above it, starts none below it, so each file is read one time on the way down."""
        def copy(call):
            return [claude_use(call, "Agent", {"description": "A copied call", "prompt": "p"}, True),
                    claude_result(call, "started", sidechain=True)]
        files = {"s1": ("toolu_S", copy("toolu_S") + copy("toolu_T") + [claude_use("w1", "Bash", {"command": "true"}, True)]),
                 "s2": ("toolu_T", copy("toolu_T") + copy("toolu_S") + [claude_use("w2", "Bash", {"command": "true"}, True)])}
        parent = [claude_use("toolu_S", "Agent", {"description": "The first", "prompt": "p"}),
                  claude_result("toolu_S", "done", {"status": "completed", "agentId": "s1"})]
        with tempfile.TemporaryDirectory() as home:
            tr = threads.Translator("claude", root="/kit", children=self.subagent_files(home, files))
            out = [r for row in parent for r in tr.records(row) if r["type"] != "session"]
        self.assertEqual([(r["tool_call_id"], r.get("status")) for r in out], [
            ("toolu_S", "in_progress"),
            ("toolu_S/toolu_S", "in_progress"), ("toolu_S/toolu_S", "completed"),          # its own call: no subagent
            ("toolu_S/toolu_T", "in_progress"),
            ("toolu_S/toolu_T/toolu_T", "in_progress"), ("toolu_S/toolu_T/toolu_T", "completed"),
            ("toolu_S/toolu_T/toolu_S", "in_progress"), ("toolu_S/toolu_T/toolu_S", "completed"),   # the one above it
            ("toolu_S/toolu_T/w2", "in_progress"),
            ("toolu_S/toolu_T", "completed"),
            ("toolu_S/w1", "in_progress"),
            ("toolu_S", "completed")])

    @staticmethod
    def shape(records):
        return [(r["type"], r.get("tool_call_id"), r.get("parent"), r.get("status")) for r in records
                if r["type"] != "session"]

    @staticmethod
    def held(records):
        """The calls that the hub holds as background work after these records, as hub.turn_records keeps them."""
        calls = {}
        for r in records:
            if r["type"] == "tool_call":
                calls[r["tool_call_id"]] = False
            elif r["type"] == "tool_call_update" and r["status"] in ("completed", "failed"):
                calls.pop(r["tool_call_id"], None)
            elif r["type"] == "tool_call_update" and r.get("background"):
                calls[r["tool_call_id"]] = True
        return sorted(call for call, background in calls.items() if background)

    # The two notices of one subagent, as Claude Code 2.1.321 wrote them on 11 November 2026 (2.1.311's own program
    # text builds the same): the subagent stopped while a command of its own ran on, and then it ended. The second
    # one names no call.
    WAITS = ('<task-notification>\n<task-id>w1</task-id>\n<tool-use-id>toolu_W</tool-use-id>\n'
             '<output-file>/tmp/tasks/w1.output</output-file>\n<status>completed</status>\n'
             '<summary>Agent "Run the tests" is waiting on its own background work</summary>\n'
             '<note>This agent stopped with background work of its own still running. It may resume on its own when '
             'that work completes or reports, and the same task-id notifies again if it does; the result below may be '
             'interim.</note>\n<result>Started.</result>\n</task-notification>')
    ENDED = ('<task-notification>\n<task-id>w1</task-id>\n<output-file>/tmp/tasks/w1.output</output-file>\n'
             '<status>completed</status>\n<summary>Agent "Run the tests" finished</summary>\n'
             '<note>A task-notification fires each time this agent stops with no live background children of its own. '
             'The user can send it another message and resume it, so the same task-id may notify more than once.'
             '</note>\n<result>The tests passed.</result>\n</task-notification>')
    FRAME = ("[SYSTEM NOTIFICATION - NOT USER INPUT]\nThis is an automated background-task event, NOT a message from "
             "the user.\n\n")

    @staticmethod
    def own_notice(task, call, status="completed"):
        """The notice of the end of a subagent's own background work, as its row in the subagent's file (2.1.321)."""
        return {"type": "user", "sessionId": SESSION, "isSidechain": True, "isMeta": True,
                "origin": {"kind": "task-notification", "producer": "session-task"},
                "message": {"role": "user", "content": FilesAndSubagents.FRAME + (
                    f"<task-notification>\n<task-id>{task}</task-id>\n" + (f"<tool-use-id>{call}</tool-use-id>\n" if call else "")
                    + f"<status>{status}</status>\n<summary>Background command \"x\" {status}</summary>\n"
                    "</task-notification>")}}

    @staticmethod
    def words(text):
        return {"type": "assistant", "sessionId": SESSION, "isSidechain": True,
                "message": {"content": [{"type": "text", "text": text}]}}

    def waiting_subagent(self):
        """A subagent in the background that starts a command of two minutes and stops, as the files of a run on
        Claude Code 2.1.321 gave it (11 November 2026): the rows of its agent's file about it, in three parts (its
        start, its first notice in each way that a notice comes, its second notice), and the subagent's own file.
        That file gives the command no task id, and the command's end notice is a row that is nobody's words."""
        def at(clock, row):
            return dict(row, timestamp=f"2026-11-11T{clock}Z")
        child = [at("10:00:00.100", {"type": "user", "sessionId": SESSION, "isSidechain": True,
                                     "message": {"role": "user", "content": "Run the tests in the background."}}),
                 at("10:00:00.200", {"type": "attachment", "isSidechain": True, "attachment": {"type": "date"}}),
                 at("10:00:05.000", claude_use("b1", "Bash", {"command": "npm test", "run_in_background": True}, True)),
                 at("10:00:05.100", claude_result("b1", "Command running in background with ID: bk1. Output is being "
                                                        "written to: /tmp/tasks/bk1.output. You will be notified when "
                                                        "it completes \u2014 do not poll that file.", sidechain=True)),
                 at("10:00:10.400", self.words("Started.")),
                 at("10:02:10.000", self.own_notice("bk1", "b1")),
                 {"type": "api-request-blob", "hash": "x"},                 # a row with no time
                 at("10:02:10.800", self.words("The tests passed."))]
        start = [at("10:00:00.000", claude_use("toolu_W", "Agent", {"description": "Run the tests", "prompt": "p",
                                                                    "subagent_type": "general-purpose"})),
                 at("10:00:00.050", claude_result("toolu_W", "Async agent launched successfully.",
                                                  {"isAsync": True, "status": "async_launched", "agentId": "w1"}))]
        first = [at("10:00:10.500", {"type": "queue-operation", "operation": "enqueue", "content": self.WAITS}),
                 at("10:00:30.000", {"type": "queue-operation", "operation": "remove", "content": self.WAITS}),
                 at("10:00:10.500", {"type": "attachment", "attachment": {"type": "queued_command", "prompt": self.WAITS}}),
                 at("10:00:30.000", {"type": "user", "sessionId": SESSION, "origin": {"kind": "task-notification"},
                                     "message": {"role": "user", "content": self.WAITS}}),
                 at("10:00:31.000", {"type": "assistant", "sessionId": SESSION, "message": {"content": [
                     {"type": "text", "text": "The subagent waits for its tests."}]}})]
        second = [at("10:02:10.900", {"type": "queue-operation", "operation": "enqueue", "content": self.ENDED}),
                  at("10:02:10.900", {"type": "attachment", "attachment": {"type": "queued_command", "prompt": self.ENDED}})]
        return child, start, first, second

    def test_a_command_that_a_subagent_left_running_stays_open_until_its_own_end(self):
        """A subagent in the background that stops while a command of its own still runs has not lost that command:
        Claude Code keeps the subagent, gives its agent a notice with the status "completed", runs the subagent again
        when the command ends and then gives a second notice (2.1.311's own program text; a run on 2.1.321, 11
        November 2026). The reader showed the command as a finished call and never read the subagent's file again: the
        hub held the task for one with nothing waiting while the command ran, asked its agent to deliver and told the
        requester of two empty turns, and the subagent's later answer never showed. The command is background work,
        one level down: it stays open under the subagent's ended call until the subagent's file shows its end."""
        child, start, first, second = self.waiting_subagent()
        files = {"w1": child[:5]}                               # the subagent's file when it stopped the first time
        tr = threads.Translator("claude", root="/kit", children=lambda agent, call=None: files.get(agent))
        out = [r for row in start + first for r in tr.records(row)]
        stopped = [("tool_call", "toolu_W", None, "in_progress"),
                   ("tool_call_update", "toolu_W", None, "in_progress"),        # launched: background work
                   ("user_message", None, "toolu_W", None),
                   ("tool_call", "toolu_W/b1", "toolu_W", "in_progress"),
                   ("tool_call_update", "toolu_W/b1", "toolu_W", "in_progress"),    # its command runs on
                   ("agent_message", None, "toolu_W", None),
                   ("tool_call_update", "toolu_W", None, "completed"),          # the subagent stopped: one end, from
                   ("agent_message", None, None, None)]                         # the first copy of its notice
        self.assertEqual(self.shape(out), stopped)
        command = next(r for r in out if r.get("tool_call_id") == "toolu_W/b1" and r["type"] == "tool_call_update")
        self.assertEqual((command.get("background"), command["output"][:38]), (True, "Command running in background with ID:"))
        self.assertEqual((self.held(out), tr.pending, tr.inside()), (["toolu_W/b1"], {}, True))
        files["w1"] = child                                     # the command ended, and the subagent ran again
        out += [r for row in second for r in tr.records(row)]
        self.assertEqual(self.shape(out)[len(stopped):], [
            ("tool_call_update", "toolu_W/b1", "toolu_W", "completed"),         # by its own notice in the subagent's file
            ("agent_message", None, "toolu_W", None),
            ("tool_call_update", "toolu_W", None, "completed")])                # once, with the rows that came
        self.assertEqual([r["text"] for r in out if r.get("parent") and r["type"] == "agent_message"],
                         ["Started.", "The tests passed."])
        self.assertNotIn("SYSTEM NOTIFICATION", json.dumps(out))                # that notice is nobody's words
        self.assertEqual((self.held(out), tr.inside()), ([], False))
        # The same files give the same records in the same places when the helper reads them again from their start,
        # with the subagent's file whole: its rows after a notice's time wait for the next notice.
        again = threads.Translator("claude", root="/kit", children=lambda agent, call=None: files.get(agent))
        self.assertEqual([r for row in start + first + second for r in again.records(row)], out)
        # The session itself can stop the subagent's command: no notice comes, and the stop is the command's end.
        files["w1"] = child[:5]
        above = threads.Translator("claude", root="/kit", children=lambda agent, call=None: files.get(agent))
        rows = start + first + [claude_use("toolu_S", "TaskStop", {"task_id": "bk1"}), claude_result("toolu_S", "Stopped")]
        some = [r for row in rows for r in above.records(row)]
        self.assertEqual(self.shape(some)[len(stopped):], [("tool_call", "toolu_S", None, "in_progress"),
                                                           ("tool_call_update", "toolu_W/b1", "toolu_W", "failed"),
                                                           ("tool_call_update", "toolu_S", None, "completed")])
        self.assertEqual((self.held(some), above.inside()), ([], False))
        # A session that ends while the command runs records no end of it that it did not see.
        files["w1"] = child[:5]
        late = threads.Translator("claude", root="/kit", children=lambda agent, call=None: files.get(agent))
        left = [r for row in start + first for r in late.records(row)] + late.finish()
        self.assertEqual((self.shape(left), self.held(left)), (stopped, ["toolu_W/b1"]))
        # A launch that names no agent: the subagent's file is found by its call, and its first notice names it for
        # the later ones, which name no call.
        with tempfile.TemporaryDirectory() as home:
            reader = self.subagent_files(home, {"w1": ("toolu_W", child[:5])})
            bare = threads.Translator("claude", root="/kit", children=reader)
            launch = dict(start[1], toolUseResult={"isAsync": True, "status": "async_launched"})
            some = [r for row in [start[0], launch] + first for r in bare.records(row)]
            with open(os.path.join(home, SESSION, "subagents", "agent-w1.jsonl"), "w") as f:
                f.write("".join(json.dumps(row) + "\n" for row in child))
            some += [r for row in second for r in bare.records(row)]
        self.assertEqual(some, out)

    def test_a_subagent_s_file_names_its_background_command_in_words(self):
        """A subagent's own file gives a command's result no task id (Claude Code 2.1.321). The command is background
        work only when its call asked for the background and its result says so in Claude Code's own words; then its
        end is its notice in that file, by its call or by its task id."""
        def run(rows):
            files = {"a1": rows}
            tr = threads.Translator("claude", root="/kit", children=lambda agent, call=None: files.get(agent))
            parent = [claude_use("toolu_A", "Agent", {"description": "Run it", "prompt": "p"}),
                      claude_result("toolu_A", "launched", {"status": "async_launched", "isAsync": True, "agentId": "a1"}),
                      {"type": "queue-operation", "operation": "enqueue", "content":
                       "<task-notification><task-id>a1</task-id><status>completed</status></task-notification>"}]
            out = [r for row in parent for r in tr.records(row)]
            return [(r["tool_call_id"], r["status"], r.get("background")) for r in out
                    if r["type"] == "tool_call_update" and r.get("parent")]
        says = ("Command running in background with ID: bk1. Output is being written to: /tmp/bk1. You will be "
                "notified when it completes.")
        asked = claude_use("b1", "Bash", {"command": "npm test", "run_in_background": True}, True)
        self.assertEqual(run([asked, claude_result("b1", says, sidechain=True)]), [("toolu_A/b1", "in_progress", True)])
        # not asked for, not said, an error, or with Claude Code's own field: as before
        plain = claude_use("b1", "Bash", {"command": "cat notes.txt"}, True)
        self.assertEqual(run([plain, claude_result("b1", says, sidechain=True)]), [("toolu_A/b1", "completed", None)])
        self.assertEqual(run([asked, claude_result("b1", "3 passed", sidechain=True)]), [("toolu_A/b1", "completed", None)])
        failed = claude_result("b1", says, sidechain=True)
        failed["message"]["content"][0]["is_error"] = True
        self.assertEqual(run([asked, failed]), [("toolu_A/b1", "failed", None)])
        self.assertEqual(run([asked, claude_result("b1", "running", {"backgroundTaskId": "bash_7"}, True)]),
                         [("toolu_A/b1", "in_progress", True)])
        self.assertEqual(run([asked, claude_result("b1", says, {"stdout": ""}, True)]),     # that field decides
                         [("toolu_A/b1", "completed", None)])
        # A command that Claude Code ends with the subagent's answer, with no notice (2.1.311's words for it): a
        # background call of it would stay open for good, so it is a finished call.
        reaped = ("Command running in background with ID: bk1. Output is being written to: /tmp/bk1. If it exits while "
                  "you are still working you will be notified, but it is terminated when you give your final response "
                  "and no notification can follow that \u2014 so do not end your turn to wait for it.")
        self.assertEqual(run([asked, claude_result("b1", reaped, sidechain=True)]), [("toolu_A/b1", "completed", None)])
        # its end: the notice in the subagent's file, by the call or by the task id alone, with its own status
        for notice, status in ((self.own_notice("bk1", "b1"), "completed"), (self.own_notice("bk1", None), "completed"),
                               (self.own_notice("bk1", "b1", "failed"), "failed")):
            self.assertEqual(run([asked, claude_result("b1", says, sidechain=True), notice]),
                             [("toolu_A/b1", "in_progress", True), ("toolu_A/b1", status, None)])
        self.assertEqual(run([asked, claude_result("b1", says, sidechain=True), self.own_notice("other", "b9")]),
                         [("toolu_A/b1", "in_progress", True)])
        # and a stop of it by the subagent itself, which gives no notice
        self.assertEqual(run([asked, claude_result("b1", says, sidechain=True),
                              claude_use("s1", "TaskStop", {"task_id": "bk1"}, True),
                              claude_result("s1", "Successfully stopped task: bk1", sidechain=True)]),
                         [("toolu_A/b1", "in_progress", True), ("toolu_A/b1", "failed", None), ("toolu_A/s1", "completed", None)])

    def test_what_a_subagent_left_in_its_background_ends_with_it(self):
        """A subagent that is over for good leaves nothing open in its background: an async subagent of its own, a
        background command, a monitor and a workflow that got no end in its file close with it, as failed. No row
        could end them later, so the hub held each for work that still ran until the session's end, and so asked
        nobody about a task whose turns ended with nothing waiting (a review, 11 November 2026). A subagent is over
        for good when its agent waited for its result, or when its notice says that it failed or was stopped: a
        subagent in the background that stopped as completed keeps what it started. The files here give each
        background call its task id, as an older Claude Code wrote a subagent's file."""
        nested = [claude_use("g1", "Read", {"file_path": "/kit/n.txt"}, True), claude_result("g1", "text", sidechain=True),
                  claude_use("c1", "Bash", {"command": "sleep 600", "run_in_background": True}, True),
                  claude_result("c1", "Command running in background with ID: bg9", {"backgroundTaskId": "bg9"}, True)]
        child = [claude_use("b1", "Bash", {"command": "npm test", "run_in_background": True}, True),
                 claude_result("b1", "Command running in background with ID: bg1", {"backgroundTaskId": "bg1"}, True),
                 claude_use("e1", "Bash", {"command": "make", "run_in_background": True}, True),
                 claude_result("e1", "Command running in background with ID: bg2", {"backgroundTaskId": "bg2"}, True),
                 self.own_notice("bg2", "e1"),                              # this one ended in the subagent's sight
                 claude_use("m1", "Monitor", {"command": "tail -f app.log", "description": "Watch the log"}, True),
                 claude_result("m1", "Monitor started", {"taskId": "mon1"}, True),
                 claude_use("f1", "Workflow", {"name": "review"}, True),
                 claude_result("f1", "launched", {"status": "async_launched", "taskId": "wf1"}, True),
                 claude_use("n1", "Agent", {"description": "Nested", "prompt": "p"}, True),
                 claude_result("n1", "launched", {"status": "async_launched", "isAsync": True, "agentId": "a2"}, True),
                 claude_use("x1", "Bash", {"command": "ls"}, True),         # a call that only has no result: as before
                 self.words("Done.")]
        files = {"a1": child, "a2": nested}

        def read(rows, finish=False):
            tr = threads.Translator("claude", root="/kit", children=lambda agent, call=None: files.get(agent))
            return [r for row in rows for r in tr.records(row)] + (tr.finish() if finish else []), tr

        def block(call):        # the subagent's own rows under its call, with what it left in its background
            return [("tool_call", f"{call}/b1", call, "in_progress"), ("tool_call_update", f"{call}/b1", call, "in_progress"),
                    ("tool_call", f"{call}/e1", call, "in_progress"), ("tool_call_update", f"{call}/e1", call, "in_progress"),
                    ("tool_call_update", f"{call}/e1", call, "completed"),
                    ("tool_call", f"{call}/m1", call, "in_progress"), ("tool_call_update", f"{call}/m1", call, "in_progress"),
                    ("tool_call", f"{call}/f1", call, "in_progress"), ("tool_call_update", f"{call}/f1", call, "in_progress"),
                    ("tool_call", f"{call}/n1", call, "in_progress"), ("tool_call_update", f"{call}/n1", call, "in_progress"),
                    ("tool_call", f"{call}/x1", call, "in_progress"),
                    ("agent_message", None, call, None),
                    ("tool_call", f"{call}/n1/g1", f"{call}/n1", "in_progress"),
                    ("tool_call_update", f"{call}/n1/g1", f"{call}/n1", "completed"),
                    ("tool_call", f"{call}/n1/c1", f"{call}/n1", "in_progress"),
                    ("tool_call_update", f"{call}/n1/c1", f"{call}/n1", "in_progress")]

        def ends(call):         # each of them closes with the subagent, one time: the deepest first, then its own
            return [("tool_call_update", f"{call}/n1/c1", f"{call}/n1", "failed"),
                    ("tool_call_update", f"{call}/n1", call, "failed"),
                    ("tool_call_update", f"{call}/b1", call, "failed"),
                    ("tool_call_update", f"{call}/f1", call, "failed"),
                    ("tool_call_update", f"{call}/m1", call, "failed")]

        def left(call):         # what the hub holds of them while they are open
            return [f"{call}/b1", f"{call}/f1", f"{call}/m1", f"{call}/n1", f"{call}/n1/c1"]
        # A subagent that its agent waited for: its result is its end.
        out, tr = read([claude_use("toolu_A", "Agent", {"description": "Run it", "subagent_type": "general-purpose", "prompt": "p"}),
                        claude_result("toolu_A", "summary", {"status": "completed", "agentId": "a1"})])
        self.assertEqual(self.shape(out), [("tool_call", "toolu_A", None, "in_progress")] + block("toolu_A")
                         + ends("toolu_A") + [("tool_call_update", "toolu_A", None, "completed")])
        self.assertEqual((self.held(out), tr.inside()), ([], False))
        self.assertEqual({r.get("interrupted") for r in out if r.get("status") == "failed"}, {False})
        # A subagent in the background that was stopped: the notice of its end.
        launch = [claude_use("toolu_K", "Agent", {"description": "Run it", "prompt": "p"}),
                  claude_result("toolu_K", "launched", {"status": "async_launched", "isAsync": True, "agentId": "a1"})]
        notice = lambda status, call="": {"type": "queue-operation", "operation": "enqueue", "content": (
            f"<task-notification>\n<task-id>a1</task-id>\n{call}<status>{status}</status>\n</task-notification>")}
        out, tr = read(launch + [notice("killed", "<tool-use-id>toolu_K</tool-use-id>\n")])
        self.assertEqual(self.shape(out)[2:], block("toolu_K") + ends("toolu_K")
                         + [("tool_call_update", "toolu_K", None, "failed")])
        self.assertEqual((self.held(out), tr.inside()), ([], False))
        # One that stopped as completed keeps what it started, also at a copy of that notice. A later notice that says
        # that it was stopped closes that, and a copy of that one gives nothing.
        out, tr = read(launch + [notice("completed", "<tool-use-id>toolu_K</tool-use-id>\n"), notice("completed")])
        self.assertEqual(self.shape(out)[2:], block("toolu_K") + [("tool_call_update", "toolu_K", None, "completed")])
        self.assertEqual((self.held(out), tr.inside()), (left("toolu_K"), True))
        more = [r for row in (notice("killed"), notice("killed")) for r in tr.records(row)]
        self.assertEqual(self.shape(more), ends("toolu_K") + [("tool_call_update", "toolu_K", None, "failed")])
        self.assertEqual((self.held(out + more), tr.inside()), ([], False))
        # A session that ends with the subagent still in its background records no end, of it or of what it started.
        out, tr = read(launch, finish=True)
        self.assertEqual(self.shape(out)[2:], block("toolu_K"))
        self.assertEqual(self.held(out), ["toolu_K"] + left("toolu_K"))


def cx(kind, payload, ts="2026-10-10T10:00:10.000Z"):
    return {"timestamp": ts, "type": kind, "payload": payload}


def cx_item(item, ts="2026-10-10T10:00:10.000Z"):
    return cx("event_msg", {"type": "item_completed", "item": item}, ts)


def cx_activity(ident, kind, thread):
    return cx_item({"type": "SubAgentActivity", "id": ident, "kind": kind, "agent_thread_id": thread, "agent_path": "/root/x"})


def cx_command(ident, command, status="completed"):
    return cx_item({"type": "CommandExecution", "id": ident, "command": ["/bin/zsh", "-lc", command], "status": status,
                    "aggregated_output": "", "exit_code": 0, "process_id": 7})


class CodexSubagents(unittest.TestCase):
    """Owner API 1.4 subagent rows from Codex 0.160 multi-agent (v2) rollouts, in their real line shapes."""
    ROOT, KID, GRANDKID, OTHER = ("019a0000-0000-7000-8000-00000000000%d" % n for n in range(4))
    FORK = "2026-10-10T10:00:05.000Z"

    def files(self):
        fork = int(threads.when(self.FORK))
        parent = [
            cx("session_meta", {"id": self.ROOT, "cwd": "/kit", "cli_version": "0.160.0", "source": "cli"}, "2026-10-10T10:00:00.000Z"),
            cx("event_msg", {"type": "task_started", "turn_id": "p-turn-1", "started_at": fork - 5}),
            cx("response_item", {"type": "function_call", "name": "spawn_agent", "namespace": "collaboration", "call_id": "call_S",
                                 "arguments": json.dumps({"task_name": "catalog_review", "fork_turns": "all", "message": "Review it"})}),
            cx_activity("call_S", "started", self.KID),
            cx("response_item", {"type": "function_call_output", "call_id": "call_S", "output": '{"task_name":"/root/catalog_review"}'}),
            cx("response_item", {"type": "function_call", "name": "spawn_agent", "namespace": "collaboration", "call_id": "call_X",
                                 "arguments": json.dumps({"task_name": "refused"})}),
            cx("response_item", {"type": "function_call_output", "call_id": "call_X", "output": "too many agents"}),
            cx_activity("subagent-completed-c-turn-1", "completed", self.KID),
            cx_activity("subagent-completed-g-turn-1", "completed", self.GRANDKID),    # a deeper agent: its own parent shows it
            cx("response_item", {"type": "function_call", "name": "followup_task", "namespace": "collaboration", "call_id": "call_F",
                                 "arguments": json.dumps({"target": "catalog_review", "message": "One more"})}),
            cx("response_item", {"type": "function_call_output", "call_id": "call_F", "output": ""}),
            cx_activity("call_router_1", "interrupted", self.KID),
            cx("event_msg", {"type": "task_complete", "turn_id": "p-turn-1"})]
        kid = [
            cx("session_meta", {"id": self.KID, "cwd": "/kit", "forked_from_id": self.ROOT, "source": {"subagent": {"thread_spawn": {
                "parent_thread_id": self.ROOT, "depth": 1, "agent_path": "/root/catalog_review"}}}}, self.FORK),
            cx("session_meta", {"id": self.ROOT, "cwd": "/kit"}, self.FORK),                          # the copied history
            cx("event_msg", {"type": "task_complete", "turn_id": "p-turn-0"}, self.FORK),
            cx("event_msg", {"type": "task_started", "turn_id": "p-turn-1", "started_at": fork - 5}, self.FORK),
            cx_command("exec-p", "echo copied from the parent"),
            cx("event_msg", {"type": "thread_settings_applied"}, self.FORK),
            cx("event_msg", {"type": "task_started", "turn_id": "c-turn-1", "started_at": fork - 1}, self.FORK),  # its own
            cx_command("exec-1", "rm -f tmp.txt"),
            cx_item({"type": "FileChange", "id": "fc-1", "status": "completed", "changes": {"/kit/a.txt": {"type": "add", "content": "x\n"}}}),
            cx("response_item", {"type": "function_call", "name": "spawn_agent", "namespace": "collaboration", "call_id": "call_N",
                                 "arguments": json.dumps({"task_name": "nested", "fork_turns": "none"})}),
            cx_activity("call_N", "started", self.GRANDKID),
            cx("response_item", {"type": "function_call_output", "call_id": "call_N", "output": "{}"}),
            cx("event_msg", {"type": "task_complete", "turn_id": "c-turn-1"}),
            cx("event_msg", {"type": "task_started", "turn_id": "c-turn-2", "started_at": fork + 9}),
            cx("response_item", {"type": "custom_tool_call", "name": "exec", "call_id": "call_E", "status": "in_progress",
                                 "input": 'await tools.exec_command({cmd: "curl -X POST outbox"})'}),
            cx("event_msg", {"type": "turn_aborted", "turn_id": "c-turn-2", "reason": "interrupted"}),
            cx("event_msg", {"type": "task_started", "turn_id": "c-turn-3", "started_at": fork + 20}),
            cx_item({"type": "AgentMessage", "id": "m-1", "content": [{"type": "Text", "text": "Still going."}]})]
        grandkid = [
            cx("session_meta", {"id": self.GRANDKID, "cwd": "/kit", "source": {"subagent": {"thread_spawn": {
                "parent_thread_id": self.KID, "depth": 2}}}}, "2026-10-10T10:00:08.000Z"),
            cx("event_msg", {"type": "task_started", "turn_id": "g-turn-1", "started_at": fork + 3}),
            cx_command("exec-g", "ls"),
            cx("event_msg", {"type": "task_complete", "turn_id": "g-turn-1"})]
        return parent, {self.KID: kid, self.GRANDKID: grandkid}

    def translate(self):
        parent, files = self.files()
        reader = lambda thread, offset: (files.get(thread, [])[offset:], len(files.get(thread, [])))
        tr = threads.Translator("codex", root="/kit", children=reader)
        return [r for row in parent for r in tr.records(row)] + tr.finish()

    def test_codex_subagents_nest_in_one_sequence_without_the_copied_history(self):
        out = self.translate()
        self.assertEqual([r["seq"] for r in out], list(range(1, len(out) + 1)))
        self.assertEqual(out, self.translate())
        rows = [(r["type"], r.get("tool_call_id"), r.get("parent"), r.get("status") or r.get("stop_reason"))
                for r in out if r["type"] != "session"]
        self.assertEqual(rows, [
            ("tool_call", "call_S", None, "in_progress"),
            ("tool_call_update", "call_S", None, "in_progress"),    # it started: background work until its end
            ("tool_call", "call_X", None, "in_progress"),
            ("tool_call_update", "call_X", None, "completed"),      # no subagent started: its output ends it
            ("tool_call", "call_S/exec-1", "call_S", "completed"),  # the subagent's first turn, at its end
            ("tool_call", "call_S/fc-1", "call_S", "completed"),
            ("tool_call", "call_S/call_N", "call_S", "in_progress"),
            ("tool_call_update", "call_S/call_N", "call_S", "in_progress"),
            ("result", None, "call_S", "end_turn"),
            ("tool_call_update", "call_S", None, "completed"),
            ("tool_call", "call_F", None, "in_progress"),
            ("tool_call_update", "call_F", None, "completed"),
            ("tool_call", "call_S/call_E", "call_S", "in_progress"),  # the interrupted follow-up turn: its call stays open
            ("result", None, "call_S", "cancelled"),
            ("result", None, None, "end_turn"),
            ("agent_message", None, "call_S", None),                  # the session is over: the rest as far as it got
            ("tool_call", "call_S/call_N/exec-g", "call_S/call_N", "completed"),
            ("result", None, "call_S/call_N", "end_turn")])
        by = {r["tool_call_id"]: r for r in out if r["type"] == "tool_call"}
        self.assertEqual((by["call_S"]["title"], by["call_S"]["subagent"]), ("Agent: catalog_review", {"name": "catalog_review"}))
        self.assertEqual(by["call_S/call_N"]["subagent"], {"name": "nested"})
        self.assertEqual(by["call_S/fc-1"]["changes"], [{"path": "a.txt", "action": "add", "added": 1, "removed": 0}])
        self.assertNotIn("copied from the parent", json.dumps(out))

    def test_a_nested_codex_subagent_is_shown_at_the_end_when_its_parent_has_nothing_left(self):
        parent, files = self.files()
        files[self.KID] = files[self.KID][:-2]         # the subagent wrote nothing after its interrupted turn
        reader = lambda thread, offset: (files.get(thread, [])[offset:], len(files.get(thread, [])))
        tr = threads.Translator("codex", root="/kit", children=reader)
        out = [r for row in parent for r in tr.records(row)] + tr.finish()
        self.assertEqual([(r["type"], r.get("tool_call_id")) for r in out[-2:]],
                         [("tool_call", "call_S/call_N/exec-g"), ("result", None)])

    def test_a_codex_subagent_that_runs_on_after_its_parent_s_turn_is_background_work(self):
        """The second code review of the runtime gaps: a parent that spawns a subagent and ends its turn left a call
        with no background mark, so the turn-end chase fired and a fresh start could stop the subagent."""
        parent, _ = self.files()
        tr = threads.Translator("codex", root="/kit", children=lambda thread, offset: ([], 0))
        out = [r for row in parent[:4] for r in tr.records(row)]          # spawned and started, nothing ended yet
        self.assertEqual([(r["type"], r.get("tool_call_id"), r.get("status"), r.get("background")) for r in out
                          if r["type"] in ("tool_call", "tool_call_update")],
                         [("tool_call", "call_S", "in_progress", None),
                          ("tool_call_update", "call_S", "in_progress", True)])

    def test_codex_subagent_files_are_read_in_steps_and_only_in_the_kit(self):
        with tempfile.TemporaryDirectory() as home, mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CODEX_HOME", None)
            kit = os.path.join(home, "kit")
            folder = os.path.join(home, ".codex", "sessions", "2026", "10", "10")
            os.makedirs(folder)
            os.makedirs(kit)
            ours = os.path.join(folder, f"rollout-2026-10-10T10-00-05-{self.KID}.jsonl")
            with open(ours, "w") as f:
                f.write(json.dumps({"type": "session_meta", "payload": {"cwd": kit}}) + "\n" + '{"type": "event_')
            with open(os.path.join(folder, f"rollout-2026-10-10T10-00-06-{self.OTHER}.jsonl"), "w") as f:
                f.write(json.dumps({"type": "session_meta", "payload": {"cwd": "/elsewhere"}}) + "\n{}\n")
            files = threads.CodexFiles(home, kit)
            rows, offset = files.subagent(self.KID)
            self.assertEqual((len(rows), rows[0]["type"]), (1, "session_meta"))     # the unfinished line waits
            with open(ours, "a") as f:
                f.write('msg", "payload": {"type": "task_started"}}\n')
            rows, offset = files.subagent(self.KID, offset)
            self.assertEqual(([r["type"] for r in rows], offset), (["event_msg"], os.path.getsize(ours)))
            self.assertEqual(files.subagent(self.OTHER), ([], 0))       # another folder's session
            self.assertEqual(files.subagent("../" + self.KID), ([], 0))


class Feeds(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fleet-threads-")
        self.home = self.tmp.name
        folder = os.path.join(self.home, ".claude", "projects", "-kit")
        os.makedirs(folder)
        self.path = os.path.join(folder, SESSION + ".jsonl")
        self.sent, self.hub_last, self.code = [], 0, 200

    def tearDown(self):
        self.tmp.cleanup()

    def post(self, batch):
        self.sent.append(batch)
        if self.code != 200:
            return self.code, {"error": "refused"}
        self.hub_last = max([self.hub_last] + [r["seq"] for r in batch["events"]])
        return 200, {"last_seq": self.hub_last}

    def tailer(self):
        return threads.Tailer("claude", lambda: [("T-7", "gen1", 2, SESSION)], self.post, home=self.home)

    def write(self, rows, partial=""):
        with open(self.path, "a") as f:
            f.write("".join(line + "\n" for line in lines(rows)) + partial)

    def test_records_are_sent_once_in_order_and_resume_after_a_restart(self):
        self.write(CLAUDE[:6], partial='{"type": "assistant"')
        tailer = self.tailer()
        tailer.scan()
        records = [r for b in self.sent for r in b["events"]]
        self.assertEqual([r["seq"] for r in records], list(range(1, 7)))
        self.assertEqual({(b["task"], b["attempt"], b["session"], b["generation"]) for b in self.sent}, {("T-7", 2, SESSION, "gen1")})
        tailer.scan()                                   # nothing new: only nothing is sent
        self.assertEqual(sum(len(b["events"]) for b in self.sent), 6)
        with open(self.path, "a") as f:                  # the writer finishes the partial line
            f.write(', "sessionId": "%s", "message": {"content": [{"type": "text", "text": "late"}]}}\n' % SESSION)
        tailer.scan()
        self.assertEqual([r["text"] for r in self.sent[-1]["events"]], ["late"])
        self.sent.clear()
        restarted = self.tailer()                        # a new helper process: it asks the hub where it stopped
        restarted.scan()
        self.assertEqual(self.sent[0]["events"], [])
        self.assertEqual(sum(len(b["events"]) for b in self.sent), 0)
        self.assertEqual(restarted.flush("T-7"), [{"session": SESSION, "last_seq": 7}])

    def test_a_failed_send_is_retried_and_an_old_attempt_stops(self):
        self.write(CLAUDE[:4])
        tailer = self.tailer()
        self.code = 503
        tailer.scan()
        self.assertIsNone(tailer.flush("T-7"))
        self.code = 200
        tailer.scan()
        self.assertEqual(self.hub_last, 4)
        self.code = 409
        self.write(CLAUDE[4:6])
        tailer.scan()
        before = len(self.sent)
        self.write(CLAUDE[6:8])
        tailer.scan()
        self.assertEqual(len(self.sent), before)        # a refused attempt sends nothing more

    def test_a_screen_window_reads_its_runner_file_and_its_last_records_wait_for_the_hub(self):
        screen = "5c2e1d4b-8a7f-4e3c-b1a2-9f8e7d6c5b4a"
        os.makedirs(os.path.join(self.home, ".fleet"))
        path = os.path.join(self.home, ".fleet", f"screen-{screen}.jsonl")
        with open(path, "w") as f:
            f.write("".join(line + "\n" for line in lines(APP[:6])))
        self.write(CLAUDE[:2])                          # a Claude task of the same agent, read in the same scans
        hub, state = {}, {"code": 200}

        def post(batch):
            if state["code"] != 200:
                return state["code"], {"error": "down"}
            stored = hub.setdefault(batch["session"], {})
            stored.update({r["seq"]: r for r in batch["events"] if r["seq"] not in stored})
            return 200, {"last_seq": max(stored, default=0)}
        live = [("T-7", "gen1", 2, SESSION, None), ("T-9", "gen1", 1, screen, "codex_app")]
        tailer = threads.Tailer("claude", lambda: list(live), post, home=self.home)
        tailer.scan()
        self.assertEqual([r["type"] for _, r in sorted(hub[SESSION].items())], ["session", "user_message"])
        self.assertEqual([r["type"] for _, r in sorted(hub[screen].items())], [
            "session", "user_message", "agent_thought", "plan", "tool_call", "tool_call_update"])
        with open(path, "a") as f:                       # the runner's last line, just before its window closed
            f.write(json.dumps(APP[6]) + "\n")
        live.pop()
        state["code"] = 503
        tailer.scan()
        self.assertIsNone(tailer.flush("T-9"))           # not sent yet, so a hold result must wait
        state["code"] = 200
        self.assertEqual(tailer.flush("T-9"), [])        # sent now; the ended session is read no more
        self.assertEqual((hub[screen][7]["tool_call_id"], hub[screen][7]["status"]), ("call_c1", "in_progress"))
        self.assertEqual(sorted(hub[screen]), list(range(1, 8)))
        self.assertEqual([k[0] for k in tailer.feeds], ["T-7"])
        self.assertIsNone(threads.screen_file("../" + screen, self.home))

    def test_a_manager_session_without_an_id_is_found_by_its_prompt_in_the_kit_folder_only(self):
        kit = os.path.join(self.home, "kit")
        os.makedirs(kit)
        prompt = "You are the manager in Founderizer. Read RULES.md first."
        mine = os.path.join(self.home, ".claude", "projects", threads.re.sub(r"[^A-Za-z0-9-]", "-", os.path.realpath(kit)))
        other = os.path.join(self.home, ".claude", "projects", "-elsewhere")
        os.makedirs(mine)
        os.makedirs(other, exist_ok=True)
        def transcript(folder, name, text, age):
            path = os.path.join(folder, name + ".jsonl")
            with open(path, "w") as f:
                f.write("\n".join(lines([{"type": "user", "isMeta": True, "message": {"content": "meta"}},
                                          {"type": "user", "message": {"content": text}}])) + "\n")
            os.utime(path, (os.path.getmtime(path) - age,) * 2)
        transcript(mine, "older-manager", prompt, 300)
        transcript(mine, "newest-manager", prompt, 100)
        transcript(mine, "a-task", "Your task is T-3.", 10)
        transcript(other, "elsewhere", prompt, 1)
        self.assertEqual(threads.manager_transcript(self.home, kit, prompt), "newest-manager")
        self.assertIsNone(threads.manager_transcript(self.home, os.path.join(self.home, "none"), prompt))

    def test_codex_rollout_is_found_by_its_marker(self):
        folder = os.path.join(self.home, ".codex", "sessions", "2026", "10", "10")
        os.makedirs(folder)
        other = os.path.join(folder, "rollout-a.jsonl")
        mine = os.path.join(folder, "rollout-b.jsonl")
        with open(other, "w") as f:
            f.write("\n".join(lines([CODEX[0], {"type": "event_msg", "payload": {"type": "item_completed", "item": {
                "type": "UserMessage", "id": "u", "content": [{"type": "text", "text": "other"}]}}}])) + "\n")
        with open(mine, "w") as f:
            f.write("\n".join(lines(CODEX[:3])) + "\n")
        env = os.environ.pop("CODEX_HOME", None)
        try:
            files = threads.CodexFiles(self.home)
            self.assertEqual(files.find(SESSION), mine)
            self.assertIsNone(threads.CodexFiles(self.home, kit="/another/folder").find(SESSION))   # cwd is /kit
            self.assertIsNone(files.find("11111111-2222-3333-4444-555555555555"))
            self.assertIsNone(files.known[other])
        finally:
            if env is not None:
                os.environ["CODEX_HOME"] = env

    def test_a_rollout_read_before_its_first_line_is_complete_is_found_later(self):
        folder = os.path.join(self.home, ".codex", "sessions", "2026", "10", "10")
        os.makedirs(folder)
        mine = os.path.join(folder, "rollout-d.jsonl")
        open(mine, "w").close()                                         # Codex made the file, nothing written yet
        env = os.environ.pop("CODEX_HOME", None)
        try:
            files = threads.CodexFiles(self.home, kit="/kit")           # as the record reader's, for one checkout
            self.assertIsNone(files.find(SESSION))
            with open(mine, "w") as f:
                f.write("\n".join(lines(CODEX[:3])) + "\n")
            self.assertEqual(files.find(SESSION), mine)                 # the same reader finds it now
        finally:
            if env is not None:
                os.environ["CODEX_HOME"] = env

    def test_a_rollout_read_before_its_first_prompt_is_found_once_the_prompt_is_written(self):
        """Codex writes a user-role row of the session's context shortly before the prompt with the marker: a scan in
        between must not take the rollout for one without a marker for good."""
        folder = os.path.join(self.home, ".codex", "sessions", "2026", "10", "10")
        os.makedirs(folder)
        mine = os.path.join(folder, "rollout-c.jsonl")
        context = {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "<environment_context>cwd /kit</environment_context>"}]}}
        with open(mine, "w") as f:      # compact, as Codex writes its rows
            f.write("\n".join(json.dumps(r, separators=(",", ":")) for r in (CODEX[0], context)) + "\n")
        env = os.environ.pop("CODEX_HOME", None)
        try:
            files = threads.CodexFiles(self.home)
            self.assertIsNone(files.find(SESSION))                      # its prompt is not written yet
            with open(mine, "a") as f:
                f.write("\n".join(lines(CODEX[1:3])) + "\n")
            self.assertEqual(files.find(SESSION), mine)                 # the same reader finds it now
        finally:
            if env is not None:
                os.environ["CODEX_HOME"] = env


THREAD = "01a12fb8-a590-7ff3-b04b-07a9551f9555"
OTHER = "11111111-2222-4333-8444-555555555555"


def primary_rollout(session=SESSION, cwd="/kit", end="task_complete"):
    """The saved rollout of a primary task in the runner, as T-107's: its marker in the first user message, one exec
    call that the code-mode host did not start, and the turn's end."""
    return [
        {"timestamp": "2026-10-12T12:46:32.000Z", "type": "session_meta", "payload": {"id": THREAD, "cwd": cwd}},
        {"type": "turn_context", "payload": {"model": "gpt-6-luna", "effort": "medium"}},
        {"type": "event_msg", "payload": {"type": "task_started", "turn_id": "turn-1"}},
        {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "UserMessage", "id": "u1",
            "content": [{"type": "text", "text": "Your task is T-7.\n\n" + threads.MARKER.format(session)}]}}},
        {"type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "call_x1",
            "input": "text(ALL_TOOLS)", "status": "completed"}},
        {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "call_x1",
            "output": "timed out negotiating with the code-mode host"}},
        {"type": "event_msg", "payload": {"type": "item_completed", "item": {"type": "AgentMessage", "id": "a1",
            "content": [{"type": "text", "text": "The tools did not start."}], "phase": "final_answer"}}},
        {"type": "event_msg", "payload": {"type": end, "turn_id": "turn-1"}},
    ]


def ended(status, error=None, turn="turn-1", thread="thr-1"):
    """The runner file's line for the end of a turn; a turn "fleet-stop" without a thread is the runner's own stop."""
    return app("turn/completed", **({"threadId": thread} if thread else {}),
               turn={"id": turn, "status": status, "error": error})


class PrimaryRunnerTasks(unittest.TestCase):
    """A primary task in the runner (an app-server task of the primary Codex runtime): its saved rollout, found by the
    session's marker, is its one source of records; the runner's own file gives only a failed end of the session."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="fleet-primary-")
        self.addCleanup(self.tmp.cleanup)
        environment = mock.patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("CODEX_HOME", None)
        self.home = self.tmp.name
        self.folder = os.path.join(self.home, ".codex", "sessions", "2026", "10", "12")
        os.makedirs(self.folder)
        os.makedirs(os.path.join(self.home, ".fleet"))
        self.hub, self.delivered, self.code = {}, [], 200
        self.live = [("T-7", "gen1", 2, SESSION, "codex_app", "none")]

    def post(self, batch):
        if self.code != 200:
            return self.code, {"error": "down"}
        stored = self.hub.setdefault(batch["session"], {})
        for record in batch["events"]:
            self.delivered.append((batch["session"], record["seq"]))
            stored.setdefault(record["seq"], record)
        return 200, {"last_seq": max(stored, default=0)}

    def tailer(self, kit=None):
        return threads.Tailer("codex", lambda: list(self.live), self.post, home=self.home, kit=kit,
                              requested={"model": "gpt-6-luna", "effort": "medium"},
                              screen_requested={"model": "gpt-6-terra", "effort": "low"})

    def rollout(self, rows, name=f"rollout-2026-10-12T12-46-32-{THREAD}.jsonl"):
        path = os.path.join(self.folder, name)
        with open(path, "a") as f:
            f.write("".join(line + "\n" for line in lines(rows)))
        return path

    def runner_file(self, rows):
        with open(os.path.join(self.home, ".fleet", f"screen-{SESSION}.jsonl"), "a") as f:
            f.write("".join(line + "\n" for line in lines(rows)))

    def records(self, session=SESSION):
        return [record for _, record in sorted(self.hub.get(session, {}).items())]

    def test_its_records_come_from_its_marked_rollout_and_not_from_the_runner_file(self):
        self.runner_file([app_item("item/completed", {"type": "agentMessage", "id": "r1", "text": "From the runner file."}),
                          ended("completed")])
        tailer = self.tailer()
        tailer.scan()                                    # no saved rollout yet: the feed waits and sends nothing
        self.assertEqual(self.records(), [])
        self.rollout(primary_rollout())
        tailer.scan()
        records = self.records()
        self.assertEqual([r["type"] for r in records], ["session", "model", "user_message", "tool_call",
                                                        "tool_call_update", "agent_message", "result"])
        self.assertEqual((records[0]["runtime"], records[0]["session_id"]), ("codex", THREAD))
        self.assertEqual((records[1]["requested_model"], records[1]["model"], records[1]["effort"]),
                         ("gpt-6-luna", "gpt-6-luna", "medium"))                # the primary settings, not the screen's
        self.assertEqual(records[2]["text"], "Your task is T-7.")              # the marker is not shown
        self.assertEqual((records[3]["title"], records[3]["kind"]), ("exec: text(ALL_TOOLS)", "execute"))
        # The host's error is shown as the runtime gave it; the rollout gives the call no failure status.
        self.assertEqual((records[4]["status"], records[4]["output"]),
                         ("completed", "timed out negotiating with the code-mode host"))
        self.assertEqual(records[6]["stop_reason"], "end_turn")
        self.assertNotIn("From the runner file.", json.dumps(records))
        self.live.clear()                                # a session that ended well gets nothing more
        tailer.scan()
        self.assertEqual(len(self.records()), 7)
        self.assertEqual(tailer.feeds, {})
        # A screen window keeps its runner file; a primary window of either needs reads the rollout.
        self.assertEqual(tailer.feed(("T-9", "gen1", 1, OTHER, "codex_app", "screen")).translator.runtime, "codex_app")
        self.assertEqual(tailer.feed(("T-9", "gen1", 1, OTHER, "codex_app")).translator.runtime, "codex_app")
        browser = tailer.feed(("T-9", "gen1", 1, OTHER, "codex_app", "browser"))
        self.assertEqual((browser.translator.runtime, browser.runner), ("codex", True))

    def test_a_failed_end_comes_one_time_from_the_runner_file_after_the_rollout(self):
        limit = {"message": "You've hit your usage limit.", "codexErrorInfo": "usageLimitExceeded"}
        model = {"message": "The 'gpt-5.6-sol' model is not supported.", "codexErrorInfo": "badRequest"}
        for case, end, last, extra in (
                ("a failed runtime turn", "task_complete", ended("failed", model),
                 [("error", "bad_request", model["message"]), ("result", "error")]),
                ("a usage limit", "task_complete", ended("failed", limit), []),
                ("a stop", "turn_aborted", ended("interrupted"), []),
                ("a normal end", "task_complete", ended("completed"), [])):
            with self.subTest(case):
                self.hub, self.delivered = {}, []
                for name in os.listdir(self.folder):
                    os.remove(os.path.join(self.folder, name))
                for name in os.listdir(os.path.join(self.home, ".fleet")):
                    os.remove(os.path.join(self.home, ".fleet", name))
                self.live = [("T-7", "gen1", 2, SESSION, "codex_app", "none")]
                self.rollout(primary_rollout(end=end))
                self.runner_file([app_item("item/completed", {"type": "agentMessage", "id": "r1", "text": "x"}), last])
                tailer = self.tailer()
                tailer.scan()
                self.live.clear()
                self.code = 503                          # the end is not sent yet: it waits, and is made one time
                tailer.scan()
                tailer.scan()
                self.code = 200
                tailer.scan()
                records = self.records()
                self.assertEqual([(r["type"], r.get("code"), r.get("message")) if r["type"] == "error" else
                                  (r["type"], r["stop_reason"]) for r in records[6:]],
                                 [("result", "cancelled" if end == "turn_aborted" else "end_turn")] + extra)
                self.assertEqual([r["seq"] for r in records], list(range(1, len(records) + 1)))
                self.assertEqual(len(self.delivered), len(set(self.delivered)))
                self.assertEqual(tailer.feeds, {})

    def test_a_task_that_ended_before_its_thread_gets_the_runners_stop_also_from_a_file_made_later(self):
        tailer = self.tailer()
        tailer.register(self.live[0])                    # the helper's start: no runner file and no rollout yet
        tailer.scan()
        self.assertEqual(self.records(), [])
        reason = "Codex did not confirm that these features are off: computer_use"
        self.runner_file([ended("failed", {"message": reason}, turn="fleet-stop", thread=None)])
        self.live.clear()
        tailer.scan()
        self.assertEqual([(r["seq"], r["type"]) for r in self.records()], [(1, "error"), (2, "result")])
        self.assertEqual((self.records()[0]["message"], self.records()[1]["stop_reason"]), (reason, "error"))
        self.assertEqual(tailer.feeds, {})

    def test_a_restarted_helper_sends_nothing_again_and_keeps_the_same_numbers(self):
        rows = primary_rollout()
        self.rollout(rows[:5])                           # the exec call has started, with no output yet
        first = self.tailer()
        first.scan()
        self.assertEqual([r["type"] for r in self.records()][-1], "tool_call")
        sent = len(self.delivered)
        restarted = self.tailer()                        # a new helper process asks the hub where it stopped
        restarted.scan()
        self.assertEqual(len(self.delivered), sent)
        self.rollout(rows[5:])
        restarted.scan()
        whole = []
        tr = threads.Translator("codex", requested={"model": "gpt-6-luna", "effort": "medium"})
        for row in rows:
            whole.extend(tr.records(row))
        self.assertEqual(self.records(), whole)          # the same records with the same numbers as one full read
        self.runner_file([ended("failed", {"message": "The turn failed."})])
        self.live.clear()
        restarted.scan()
        self.assertEqual([(r["seq"], r["type"]) for r in self.records()[-2:]],
                         [(len(whole) + 1, "error"), (len(whole) + 2, "result")])
        self.assertEqual(len(self.delivered), len(set(self.delivered)))

    def test_an_unreadable_terminal_record_keeps_the_feed_for_the_next_scan(self):
        self.rollout(primary_rollout())
        self.runner_file([ended("failed", {"message": "The turn failed."})])
        tailer = self.tailer()
        tailer.scan()
        self.live.clear()
        real_open = open
        def unavailable(path, *args, **kwargs):
            if str(path).endswith("screen-" + SESSION + ".jsonl"):
                raise PermissionError("temporarily unreadable")
            return real_open(path, *args, **kwargs)
        with mock.patch("builtins.open", side_effect=unavailable):
            self.assertIsNone(tailer.flush("T-7"))
        feed = tailer.feeds[("T-7", SESSION)]
        self.assertFalse(feed.closed)
        self.assertFalse(feed.ended)
        tailer.scan()
        self.assertEqual([r["type"] for r in self.records()][-2:], ["error", "result"])
        self.assertEqual(self.records()[-1]["stop_reason"], "error")
        self.assertEqual(tailer.feeds, {})
        self.assertEqual(len(self.delivered), len(set(self.delivered)))

    def test_a_stop_during_an_exec_call_leaves_the_call_open(self):
        rows = primary_rollout(end="turn_aborted")
        self.rollout(rows[:5] + rows[7:])                # the stop came while the script ran: no output
        self.runner_file([ended("interrupted")])
        tailer = self.tailer()
        tailer.scan()
        self.live.clear()
        tailer.scan()
        records = self.records()
        self.assertEqual([(r["type"], r.get("status") or r.get("stop_reason")) for r in records[3:]],
                         [("tool_call", "in_progress"), ("result", "cancelled")])
        self.assertEqual(records[3]["kind"], "execute")  # an effectful call with no end: the hub's unknown outcome

    def test_another_sessions_rollout_is_never_read(self):
        self.rollout(primary_rollout(session=OTHER), name="rollout-a-other.jsonl")             # another session
        self.rollout(primary_rollout(cwd="/elsewhere"), name="rollout-b-elsewhere.jsonl")      # another folder
        tailer = self.tailer(kit="/kit")
        tailer.scan()
        self.assertEqual(self.records(), [])
        known = tailer.codex.known
        self.assertEqual((known[os.path.join(self.folder, "rollout-a-other.jsonl")],
                          known[os.path.join(self.folder, "rollout-b-elsewhere.jsonl")]), (OTHER, None))
        mine = primary_rollout()
        mine[6]["payload"]["item"]["content"][0]["text"] = "Only in this session's rollout."
        self.rollout(mine)
        tailer.scan()
        self.assertEqual([r["text"] for r in self.records() if r["type"] == "agent_message"],
                         ["Only in this session's rollout."])


if __name__ == "__main__":
    unittest.main()

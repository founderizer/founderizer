"""Numeric usage checks. Fixtures only: no AI or provider calls."""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import hub
import usage
from test_ui_api import OwnerAPI


def tokens(runtime="claude"):
    return dict(input=10, output=20, cache_read=30, cache_write=40, total=100,
                sessions=2, since=1000, last_activity=2000, collected_at=3000,
                source=usage.SOURCES[runtime], scope=usage.SCOPE, error=None)


def limits(runtime="claude"):
    return dict(collected_at=3000, source=usage.LIMIT_SOURCES[runtime], plan="Claude Max 5x",
                account_key="anthropic:" + "a" * 32,
                windows=[dict(id="session:0", label="5 hours", used_percent=14.5,
                              resets_at=20000, window_minutes=300)], error=None)


def cx(kind, payload, ts="2026-10-27T10:00:00.000Z"):
    """One line of a Codex rollout."""
    return dict(type=kind, timestamp=ts, payload=payload)


def count(total, last=None, ts="2026-10-27T10:00:00.000Z"):
    """A Codex token_count event: its running total and, as Codex gives it since 0.159, the call's own usage, each as
    (input, cached input, output)."""
    def kinds(values):
        return dict(input_tokens=values[0], cached_input_tokens=values[1], output_tokens=values[2])
    info = dict(total_token_usage=kinds(total), **({"last_token_usage": kinds(last)} if last else {}))
    return cx("event_msg", dict(type="token_count", info=info), ts)


class TokenRecords(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.kit = str((self.home / "fleet-pilot").resolve())
        self.root = self.home / ".claude/projects" / usage.re.sub(r"[^A-Za-z0-9-]", "-", self.kit)
        self.root.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, rows):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(x) + "\n" for x in rows))

    def claude_row(self, mid="msg1", session="s1", output=5, cwd=None):
        return dict(type="assistant", cwd=cwd or self.kit, sessionId=session,
                    timestamp="2026-10-10T10:00:00Z", message=dict(id=mid, usage=dict(
                        input_tokens=2, output_tokens=output, cache_read_input_tokens=100,
                        cache_creation_input_tokens=20, output_tokens_details={"thinking_tokens": 3}),
                        content=[{"type": "text", "text": "PRIVATE_CONTENT_MUST_NOT_LEAVE_HOST"}]))

    def test_claude_blocks_forks_and_other_workspaces_are_not_double_counted(self):
        self.write(self.root / "s1.jsonl", [self.claude_row(), self.claude_row(output=10),
                                            self.claude_row(mid="other", session="s3", cwd="/another")])
        self.write(self.root / "s2.jsonl", [self.claude_row(session="s2", output=10), self.claude_row(mid="msg2", session="s2")])
        data = usage.transcript_tokens("claude", self.kit, self.home)
        self.assertEqual([data[k] for k in usage.TOKEN_KEYS], [4, 15, 200, 40])
        self.assertEqual(data["total"], 259)
        self.assertEqual(data["sessions"], 2)
        self.assertNotIn("PRIVATE", json.dumps(data))

    def test_a_workflow_s_agents_count_in_their_session_s_totals(self):
        """AUTONOMY.md decision 41: a Workflow's agents write their own transcripts below the session's folder, as
        Claude Code 2.1.308 wrote them against a stand-in (28 October 2026): sidechain rows with the root session's
        id, their own message ids and usage, beside the run's journal and meta files. Their tokens and calls count in
        that session's totals; the session's own first call and model stay its own."""
        main = [dict(self.claude_row(mid="main1"), isSidechain=False),
                dict(self.claude_row(mid="main2", output=7), isSidechain=False)]
        for row in main:
            row["message"]["model"] = "claude-opus-5-5"
        self.write(self.root / "s1.jsonl", main)
        run = self.root / "s1" / "subagents" / "workflows" / "wf_ad53e04e-8f4"
        for agent, mid in (("a3573d4036034ab3e", "w1"), ("a0eaeda340be46713", "w2")):
            row = self.claude_row(mid=mid, output=50)
            row["message"]["model"] = "claude-sonnet-5"
            self.write(run / f"agent-{agent}.jsonl", [
                dict(type="user", isSidechain=True, sessionId="s1", cwd=self.kit, agentId=agent,
                     message=dict(role="user", content="[Workflow harness — computed task] Read part one")),
                dict(type="api-request", sessionId="s1", agentId=agent, id="req1"),
                dict(row, isSidechain=True, agentId=agent)])
            (run / f"agent-{agent}.meta.json").write_text('{"agentType": "workflow-subagent"}')
        self.write(run / "journal.jsonl", [dict(type="launched"), dict(type="result", agentId="a0eaeda340be46713",
                                                                       result="DONE.")])
        self.write(self.root / "s1" / "subagents" / "agent-a9.jsonl",       # a subagent of the Agent tool, as before
                   [dict(self.claude_row(mid="sub1", output=1), isSidechain=True)])
        data = usage.transcript_tokens("claude", self.kit, self.home)
        (session,) = data["by_session"]
        self.assertEqual((session["session_id"], session["calls"]), ("s1", 5))
        self.assertEqual([session[k] for k in usage.TOKEN_KEYS], [10, 5 + 7 + 50 + 50 + 1, 500, 100])
        self.assertEqual(session["total"], data["total"])
        self.assertEqual(data["sessions"], 1)
        self.assertEqual(session["model"], "claude-opus-5-5")      # its own newest call's, not an agent's
        self.assertEqual(session["first_cache_share"], round(100 / 122, 4))

    def test_codex_uses_latest_cumulative_per_session_and_cache_is_a_subset(self):
        root = self.home / ".codex/sessions"
        def event(i, o, c):
            return dict(type="event_msg", timestamp="2026-10-10T11:00:00Z", payload=dict(type="token_count", info=dict(
                total_token_usage=dict(input_tokens=i, output_tokens=o, cached_input_tokens=c, reasoning_output_tokens=o))))
        meta = dict(type="session_meta", payload=dict(id="id1", cwd=self.kit))
        self.write(root / "a.jsonl", [meta, event(100, 5, 80), event(300, 20, 200), event(300, 20, 200)])
        self.write(root / "copy.jsonl", [meta, event(300, 20, 200)])
        self.write(root / "other.jsonl", [dict(type="session_meta", payload=dict(id="id2", cwd="/other")), event(9999, 50, 0)])
        data = usage.transcript_tokens("codex", self.kit, self.home)
        self.assertEqual([data[k] for k in usage.TOKEN_KEYS], [100, 20, 200, 0])
        self.assertEqual(data["total"], 320)
        self.assertEqual(data["sessions"], 1)

    def test_a_partial_last_line_waits_and_an_invalid_complete_line_is_passed_over(self):
        """A line that a writer is still finishing is read at a later scan. A complete line that is not JSON raised
        before its offset moved, so every later scan stopped at that same line and the reading never moved again: it
        is passed over now, and the lines after it count."""
        path, scan = self.root / "s.jsonl", usage.Scan()
        self.write(path, [self.claude_row()])
        with path.open("a") as f:
            f.write('{"type": "assistant", "unfinished":')
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home, scan)["total"], 127)
        self.assertEqual(scan.files[path].offset, len(json.dumps(self.claude_row())) + 1)      # it waits there
        with path.open("a") as f:
            f.write("\n" + json.dumps(self.claude_row(mid="msg2")) + "\n")
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home, scan)["total"], 254)
        self.assertEqual(scan.files[path].offset, path.stat().st_size)
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home)["total"], 254)     # a scan from its start
        with path.open("a") as f:           # JSON that is not of a record's shape is passed over in the same way
            f.write(json.dumps({"type": "assistant", "message": "text"}) + "\n" + json.dumps(self.claude_row(mid="msg3"))
                    + "\n")
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home, scan)["total"], 381)
        self.assertEqual(scan.files[path].offset, path.stat().st_size)

    def test_a_worktree_agent_and_rows_after_a_change_of_folder_count_in_their_session(self):
        """A sub-agent with worktree isolation runs in a worktree of the checkout, and a session that changed its
        folder writes its later rows with that folder: both are the session's own work. A session that never ran in
        the checkout is another workspace's, wherever its rows are."""
        worktree = self.kit + "/.claude/worktrees/agent-a1"
        self.write(self.root / "s1.jsonl", [self.claude_row(mid="m1"), self.claude_row(mid="m2", cwd="/srv/repo")])
        self.write(self.root / "s1" / "subagents" / "agent-a1.jsonl",
                   [dict(self.claude_row(mid="w1", cwd=worktree), isSidechain=True)])
        self.write(self.root / "s9.jsonl", [self.claude_row(mid="x1", session="s9", cwd="/another")])
        data = usage.transcript_tokens("claude", self.kit, self.home)
        self.assertEqual([(r["session_id"], r["calls"], r["total"]) for r in data["by_session"]], [("s1", 3, 3 * 127)])
        self.assertEqual((data["total"], data["sessions"]), (3 * 127, 1))
        # Codex: an agent that runs in a worktree of the checkout is its root session's
        self.codex("rollout-root.jsonl", [cx("session_meta", dict(id=self.ROOT, session_id=self.ROOT, cwd=self.kit)),
                                          count((100, 0, 1), (100, 0, 1))])
        self.codex("rollout-kid.jsonl", [cx("session_meta", dict(id=self.KID, session_id=self.ROOT, cwd=worktree,
                                                                 source={"subagent": {"thread_spawn": {}}})),
                                         count((40, 0, 1), (40, 0, 1))])
        data = usage.transcript_tokens("codex", self.kit, self.home)
        self.assertEqual([(r["session_id"], r["total"]) for r in data["by_session"]], [(self.ROOT, 142)])

    ROOT, KID, GRANDKID = ("019a0000-0000-7000-8000-00000000000%d" % n for n in range(1, 4))

    def codex(self, name, rows):
        self.write(self.home / ".codex/sessions/2026/10/27" / name, rows)

    def test_a_forked_codex_agent_counts_its_own_calls_once_at_its_own_model(self):
        """A Codex sub-agent's rollout starts with a copy of its parent's history (threads.codex_own_start). As Codex
        0.163 to 0.165 write it, its first line names its root session and the ordinal of its own first row, and the
        copy starts with the parent's own first line. Only its own rows count, each call once with its own usage, at
        its own model, in its root session; the parent's calls stay the parent's."""
        self.codex("rollout-root.jsonl", [cx("session_meta", dict(id=self.ROOT, session_id=self.ROOT, cwd=self.kit)),
                                          cx("turn_context", dict(model="gpt-6.1-sol")),
                                          count((1000, 800, 50), (1000, 800, 50)),
                                          count((2500, 2000, 120), (1500, 1200, 70))])
        spawn = {"subagent": {"thread_spawn": {"parent_thread_id": self.ROOT, "depth": 1}}}
        self.codex("rollout-kid.jsonl", [
            cx("session_meta", dict(id=self.KID, session_id=self.ROOT, forked_from_id=self.ROOT, cwd=self.kit,
                                    source=spawn, subagent_history_start_ordinal=5)),
            cx("session_meta", dict(id=self.ROOT, session_id=self.ROOT, cwd=self.kit)),    # the copied history
            cx("turn_context", dict(model="gpt-6.1-sol")), count((1000, 800, 50), (1000, 800, 50)),
            cx("event_msg", dict(type="task_started", turn_id="p-1")),
            cx("event_msg", dict(type="thread_settings_applied")),                         # its own rows
            cx("event_msg", dict(type="task_started", turn_id="c-1")), cx("turn_context", dict(model="gpt-6-luna")),
            count((300, 100, 20), (300, 100, 20)), count((700, 400, 45), (400, 300, 25)),
            count((700, 400, 45), (400, 300, 25))])                                        # the same call again
        data = usage.transcript_tokens("codex", self.kit, self.home)
        (root,) = data["by_session"]
        self.assertEqual({k: root[k] for k in ("session_id", "input", "cache_read", "cache_write", "output", "calls",
                                               "model", "models")},
                         dict(session_id=self.ROOT, input=800, cache_read=2400, cache_write=0, output=165, calls=4,
                              model="gpt-6.1-sol", models=[["gpt-6.1-sol", 500, 2000, 0, 120, 2],
                                                           ["gpt-6-luna", 300, 400, 0, 45, 2]]))
        self.assertEqual((data["total"], data["sessions"]), (3365, 2))
        usage.validate_usage(dict(tokens=data, limits=None), "codex")

    def test_an_older_codex_fork_and_a_nested_agent_count_in_their_root_session(self):
        """Codex 0.160 names no root session and no ordinal: a fork's own rows start at its first turn that started
        at the fork (started_at is in whole seconds, up to a second before the file's first line), and a nested
        agent's root is its parent's. Here the fork's running total goes on from the copied one; each call counts
        with its own usage."""
        fork = "2026-10-10T10:00:05.000Z"
        at = int(usage.timestamp(fork))

        def spawn(parent):
            return {"subagent": {"thread_spawn": {"parent_thread_id": parent, "depth": 1}}}
        self.codex("rollout-root.jsonl", [
            cx("session_meta", dict(id=self.ROOT, cwd=self.kit, source="cli"), "2026-10-10T10:00:00.000Z"),
            cx("event_msg", dict(type="task_started", turn_id="p-1", started_at=at - 5)),
            cx("turn_context", dict(model="gpt-6.1-sol")),
            count((1000, 800, 50), (1000, 800, 50)), count((2500, 2000, 120), (1500, 1200, 70))])
        self.codex("rollout-kid.jsonl", [
            cx("session_meta", dict(id=self.KID, cwd=self.kit, forked_from_id=self.ROOT, source=spawn(self.ROOT)),
               fork),
            cx("session_meta", dict(id=self.ROOT, cwd=self.kit), fork),
            cx("event_msg", dict(type="task_started", turn_id="p-1", started_at=at - 5), fork),
            cx("turn_context", dict(model="gpt-6.1-sol"), fork), count((1000, 800, 50), (1000, 800, 50), fork),
            cx("event_msg", dict(type="task_started", turn_id="c-1", started_at=at - 1), fork),
            cx("turn_context", dict(model="gpt-6-luna")),
            count((1300, 900, 70), (300, 100, 20)), count((1700, 1200, 95), (400, 300, 25))])
        self.codex("rollout-grandkid.jsonl", [
            cx("session_meta", dict(id=self.GRANDKID, cwd=self.kit, source=spawn(self.KID))),
            cx("turn_context", dict(model="gpt-6-luna")), count((200, 0, 10), (200, 0, 10))])
        data = usage.transcript_tokens("codex", self.kit, self.home)
        (root,) = data["by_session"]
        self.assertEqual({k: root[k] for k in ("session_id", "input", "cache_read", "output", "calls", "model",
                                               "models")},
                         dict(session_id=self.ROOT, input=1000, cache_read=2400, output=175, calls=5,
                              model="gpt-6.1-sol", models=[["gpt-6.1-sol", 500, 2000, 0, 120, 2],
                                                           ["gpt-6-luna", 500, 400, 0, 55, 3]]))
        self.assertEqual(data["sessions"], 3)

    def test_a_resumed_codex_session_counts_each_run(self):
        """An older Codex (0.147, 0.150) that resumes a session writes on in the same rollout, and its running total
        starts again from nothing: each call counts, not the largest total."""
        self.codex("rollout-a.jsonl", [cx("session_meta", dict(id=self.ROOT, cwd=self.kit)),
                                       count((1000, 0, 10)), count((3000, 0, 30)),       # before the resume
                                       count((500, 0, 5)), count((1500, 0, 15))])         # after it
        data = usage.transcript_tokens("codex", self.kit, self.home)
        self.assertEqual((data["input"], data["output"], data["by_session"][0]["calls"]), (4500, 45, 4))

    def test_more_files_than_a_scan_once_took_all_count(self):
        """Every workflow agent writes a file of its own: 5,001 files are no limit."""
        for n in range(5001):
            (self.root / f"s{n}.jsonl").write_text(json.dumps(self.claude_row(mid=f"m{n}", session=f"s{n}")) + "\n")
        data = usage.transcript_tokens("claude", self.kit, self.home)
        self.assertEqual((data["sessions"], data["total"], len(data["by_session"])),
                         (5001, 5001 * 127, usage.BY_SESSION))

    def test_a_scan_out_of_its_bounds_goes_on_where_it_stopped_and_gives_no_partial_total(self):
        for n in range(3):
            self.write(self.root / f"s{n}.jsonl", [self.claude_row(mid=f"a{n}", session=f"s{n}"),
                                                   self.claude_row(mid=f"b{n}", session=f"s{n}")])
        whole = usage.transcript_tokens("claude", self.kit, self.home)
        scan, scans = usage.Scan(), 0
        with patch("usage.MAX_BYTES", 10):
            with self.assertRaises(usage.ScanPending):
                usage.transcript_tokens("claude", self.kit, self.home)      # alone, a scan gives no partial total
            while True:
                scans += 1
                try:
                    data = usage.transcript_tokens("claude", self.kit, self.home, scan)
                    break
                except usage.ScanPending:
                    self.assertLess(scans, 6)
        self.assertEqual(scans, 6)                                          # one line a scan, and none read twice
        drop = lambda reading: {k: v for k, v in reading.items() if k != "collected_at"}
        self.assertEqual(drop(data), drop(whole))

    def test_an_unchanged_file_is_not_read_again_and_a_grown_one_only_from_where_it_stopped(self):
        path = self.root / "s1.jsonl"
        self.write(path, [self.claude_row(mid="m1")])
        scan = usage.Scan()
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home, scan)["total"], 127)
        self.assertEqual(scan.read, path.stat().st_size)
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home, scan)["total"], 127)
        self.assertEqual(scan.read, 0)                                       # nothing changed: nothing read
        line = json.dumps(self.claude_row(mid="m2")) + "\n"
        with path.open("a") as f:
            f.write(line)
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home, scan)["total"], 254)
        self.assertEqual(scan.read, len(line))                               # only what it gained
        self.write(path, [self.claude_row(mid="m3", output=6)])              # written again: read from its start
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home, scan)["total"], 128)
        before = path.stat().st_mtime_ns
        self.write(path, [self.claude_row(mid="m4", output=7)])              # the same size, written again
        os.utime(path, ns=(before + 10**6, before + 10**6))                  # at another time, as a write is
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home, scan)["total"], 129)
        path.unlink()
        self.assertIsNone(usage.transcript_tokens("claude", self.kit, self.home, scan))

    def test_a_line_longer_than_any_token_record_is_passed_over(self):
        """A tool's output can make a transcript line of many megabytes (15 MB in a Codex rollout of 27 October
        2026): it holds no token record, and it no longer stops the scan."""
        big = dict(type="user", sessionId="s1", cwd=self.kit, message=dict(content="x" * (5 * 1024 * 1024)))
        self.write(self.root / "s1.jsonl", [self.claude_row(mid="m1"), big, self.claude_row(mid="m2")])
        self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home)["total"], 254)
        with patch("usage.MAX_ROW", 4096):                                   # longer than a row is ever read
            self.assertEqual(usage.transcript_tokens("claude", self.kit, self.home)["total"], 254)

    def test_the_collector_keeps_its_scan_and_one_that_goes_on_keeps_the_last_reading(self):
        path = self.root / "s1.jsonl"
        self.write(path, [self.claude_row(mid="m1")])
        collector = usage.Collector(self.kit, "hand", "claude", lambda data: (200, {}), self.home)
        collector.last_poll = time.time()                                    # its account was read just now
        collector.collect()
        self.assertEqual(collector.data["tokens"]["total"], 127)
        with path.open("a") as f:
            f.write("".join(json.dumps(self.claude_row(mid=m)) + "\n" for m in ("m2", "m3")))
        with patch("usage.MAX_BYTES", 10):
            collector.collect()                                              # one line: it goes on at the next
            self.assertEqual((collector.data["tokens"]["total"], collector.data["tokens"]["error"]), (127, None))
            collector.collect()
        self.assertEqual(collector.data["tokens"]["total"], 3 * 127)

    def test_the_sessions_of_an_acp_program_are_read_from_the_runners_usage_files(self):
        """The collector's third source (the AI providers build spec, section 3.7): the usage file that the ACP runner
        keeps for each session, ~/.fleet/acp/<fleet session>.json. A session's row has the fleet's own session id,
        its four kinds, its calls and each model apart, and only the files of this checkout and this runtime count."""
        import acp_runner
        folder = self.home / ".fleet" / "acp"
        first, second = "11111111-2222-4333-8444-555555555555", "11111111-2222-4333-8444-666666666666"
        spent = acp_runner.Usage(str(folder / f"{first}.json"), first, self.kit, "grok")
        spent.add({"models": {"grok-4.7": [400, 600, 0, 50, 2]}, "context": {"used": 700, "size": 500000}},
                  "grok-4.7", now=1794420000.0)
        spent.add({"models": {"grok-4.7": [300, 900, 10, 40, 1], "grok-4.5": [100, 0, 0, 20, 1]}, "context": None},
                  "grok-4.7", now=1794420300.0)
        acp_runner.Usage(str(folder / f"{second}.json"), second, self.kit, "grok").add(
            {"models": {"grok-4.5": [10, 0, 0, 5, 1]}, "context": None}, "grok-4.5", now=1794420100.0)
        # another checkout's session, another program's, and files that are no usage files
        acp_runner.Usage(str(folder / "other-kit.json"), "other-kit", "/elsewhere", "grok").add(
            {"models": {"grok-4.7": [9, 9, 9, 9, 9]}}, "grok-4.7")
        acp_runner.Usage(str(folder / "other-program.json"), "other-program", self.kit, "opencode").add(
            {"models": {"own/m": [7, 7, 7, 7, 7]}}, "own/m")
        (folder / "broken.json").write_text("{\"session_id\": ")
        (folder / "list.json").write_text("[1, 2, 3]")
        (folder / "negative.json").write_text(json.dumps({"session_id": "negative", "kit": self.kit, "runtime": "grok",
                                                          "models": {"m": [-1, 0, 0, 5, 1]}}))
        (folder / f"{first}.json.part").write_text("{}")
        reading = usage.transcript_tokens("grok", self.kit, self.home)
        self.assertEqual({k: reading[k] for k in ("input", "cache_read", "cache_write", "output", "total", "sessions")},
                         {"input": 810, "cache_read": 1500, "cache_write": 10, "output": 115, "total": 2435,
                          "sessions": 2})
        self.assertEqual((reading["source"], reading["since"], reading["last_activity"]),
                         ("ACP session records", 1794420000.0, 1794420300.0))
        rows = {row["session_id"]: row for row in reading["by_session"]}
        self.assertEqual(sorted(rows), [first, second])
        self.assertEqual(rows[first], {
            "session_id": first, "total": 2420, "last_activity": 1794420300.0, "input": 800, "output": 110,
            "cache_read": 1500, "cache_write": 10, "calls": 4, "model": "grok-4.7",
            "first_cache_share": 0.6,       # of the first turn: 600 of the 1000 tokens that it read came from the cache
            "models": [["grok-4.7", 700, 1500, 10, 90, 3], ["grok-4.5", 100, 0, 0, 20, 1]]})
        self.assertEqual(usage.validate_usage({"tokens": reading, "limits": None}, "grok")["tokens"], reading)
        self.assertEqual(usage.transcript_tokens("opencode", self.kit, self.home)["by_session"][0]["model"], "own/m")
        self.assertIsNone(usage.transcript_tokens("grok", str(self.home / "another-kit"), self.home))
        # a runtime with this source sends no limits, and a report of it with limits is refused
        with self.assertRaises(ValueError):
            usage.validate_usage({"tokens": reading, "limits": limits("codex")}, "grok")
        with self.assertRaises(ValueError):
            usage.validate_usage({"tokens": tokens("codex"), "limits": None}, "grok")

    def test_claude_scoped_windows_and_original_cache_time(self):
        cache = dict(oauthAccount=dict(accountUuid="safe-id", userRateLimitTier="default_claude_max_5x"),
                     cachedUsageUtilization=dict(accountUuid="safe-id", fetchedAtMs=3000000, utilization=dict(limits=[
                         dict(kind="session", group="session", percent=0, resets_at="2026-10-10T12:00:00+00:00", scope=None),
                         dict(kind="weekly_scoped", group="weekly", percent=20, resets_at=None,
                              scope=dict(model=dict(display_name="Fable")))])))
        (self.home / ".claude.json").write_text(json.dumps(cache))
        data = usage.claude_cache(self.home)
        self.assertEqual(data["collected_at"], 3000)
        self.assertEqual(data["windows"][1]["label"], "7 days (Fable)")
        self.assertEqual(data["windows"][0]["used_percent"], 0)
        self.assertNotIn("safe-id", json.dumps(data))
        cache["cachedUsageUtilization"]["accountUuid"] = "old-account"
        (self.home / ".claude.json").write_text(json.dumps(cache))
        with self.assertRaises(ValueError):                         # another account's windows are never used
            usage.claude_cache(self.home)

    def test_codex_multi_bucket_wins_and_keeps_independent_windows(self):
        window = dict(usedPercent=1, windowDurationMins=10080, resetsAt=20000)
        data = usage.normalize_codex_limits(dict(accountId="account", rateLimits=dict(primary=dict(window, usedPercent=99)),
            rateLimitsByLimitId=dict(codex=dict(primary=window, secondary=None), other=dict(primary=dict(window, usedPercent=20)))),
            dict(planType="prolite", email="PRIVATE_EMAIL"), 3000)
        self.assertEqual([x["used_percent"] for x in data["windows"]], [1, 20])
        self.assertNotIn("PRIVATE_EMAIL", json.dumps(data))
        self.assertEqual(data["plan"], "prolite")

    def test_the_account_email_is_the_runtimes_own_and_never_changes_the_account_key(self):
        result = dict(accountId="account", rateLimits=dict(primary=dict(usedPercent=1, windowDurationMins=10080, resetsAt=20000)))
        data = usage.normalize_codex_limits(result, dict(planType="prolite", email="owner@example.com"), 3000)
        other = usage.normalize_codex_limits(result, dict(planType="prolite", email="second@example.com"), 3000)
        self.assertEqual((data["account_email"], other["account_email"]), ("owner@example.com", "second@example.com"))
        self.assertEqual(data["account_key"], other["account_key"])            # the account identity alone decides
        for bad in (None, 7, "", "no-at-sign", "two@@example.com", "a b@example.com", "a@b\nc", "a@b\x00c",
                    "x" * 250 + "@example.com"):
            self.assertIsNone(usage.normalize_codex_limits(result, dict(email=bad), 3000)["account_email"])
        cache = dict(oauthAccount=dict(accountUuid="safe-id", organizationUuid="org", emailAddress="owner@example.com"),
                     cachedUsageUtilization=dict(accountUuid="safe-id", fetchedAtMs=3000000,
                                                 utilization=dict(five_hour=dict(utilization=3, resets_at=None))))
        (self.home / ".claude.json").write_text(json.dumps(cache))
        # Claude: the email is the one that the runtime's own sign-in status gave, and only for this account record.
        claude = usage.claude_cache(self.home, "Owner@Example.com")
        self.assertEqual((claude["account_email"], claude["collected_at"]), ("Owner@Example.com", 3000))
        self.assertEqual(claude["account_key"], usage.account_key("anthropic", "safe-id:org"))
        self.assertNotIn("safe-id", json.dumps(claude))
        for unconfirmed in (None, "", "other@example.com"):          # no status, no email, or another account's
            self.assertIsNone(usage.claude_cache(self.home, unconfirmed)["account_email"])
        self.assertEqual(usage.claude_cache(self.home, "other@example.com")["account_key"], claude["account_key"])

    def test_a_signed_out_claude_with_an_old_account_record_gives_no_fresh_identity(self):
        record = dict(accountUuid="safe-id", organizationUuid="org", emailAddress="owner@example.com")
        old = dict(accountUuid="safe-id", fetchedAtMs=3000000, utilization=dict(five_hour=dict(utilization=3, resets_at=None)))
        ok, out = dict(num_turns=0, is_error=False), dict(loggedIn=False, email=None)
        signed = dict(loggedIn=True, email="owner@example.com")

        def collect(config, usage_answer, status_answer):
            """One poll of a new helper: the account record on disk, the /usage command and the sign-in status."""
            (self.home / ".claude.json").write_text(json.dumps(config))
            (self.home / ".fleet" / "usage-manager.json").unlink(missing_ok=True)
            collector = usage.Collector(self.kit, "manager", "claude", lambda data: None, self.home)

            def run(args, cwd, timeout=25, ok=(0,)):
                answer = status_answer if args[1:3] == ["auth", "status"] else usage_answer
                if isinstance(answer, Exception):
                    raise answer
                return answer

            with patch("usage.transcript_tokens", return_value=tokens()), patch("usage.run_json", side_effect=run):
                collector.collect()
            return collector.data["limits"]

        bare = dict(oauthAccount=record, cachedUsageUtilization=dict(accountUuid="safe-id", fetchedAtMs=3000000, utilization={}))
        failed = ValueError("CLI read failed")
        # Signed out: the account record and its cache are still on disk. Without windows there is no reading at all.
        self.assertIsNone(collect(bare, failed, failed))
        self.assertIsNone(collect(bare, ok, out))                    # the runtime itself says signed out
        self.assertIsNone(collect(bare, ok, failed))                 # the status could not be read: not a sign-in
        self.assertIsNone(collect(dict(oauthAccount=record), dict(num_turns=0, is_error=True), signed))
        # With old windows: a runtime that says signed out gives no reading; when nothing can be read, the windows
        # keep their own old time, with an error and no email. Never a reading of now.
        self.assertIsNone(collect(dict(oauthAccount=record, cachedUsageUtilization=old), ok, out))
        stale = collect(dict(oauthAccount=record, cachedUsageUtilization=old), failed, failed)
        self.assertEqual((stale["collected_at"], stale["account_email"], stale["error"]),
                         (3000, None, "Account limits could not be refreshed."))
        stale = collect(dict(oauthAccount=record, cachedUsageUtilization=old), ok, failed)
        self.assertEqual((stale["collected_at"], stale["account_email"], stale["error"]),
                         (3000, None, "Account limit data is not current."))
        # Signed in, as the runtime itself says: the account alone is a reading of now, with its email.
        fresh = collect(bare, ok, signed)
        self.assertEqual((fresh["windows"], fresh["error"], fresh["account_email"]), ([], usage.NO_WINDOWS, "owner@example.com"))
        self.assertAlmostEqual(fresh["collected_at"], time.time(), delta=5)
        self.assertEqual(fresh["account_key"], usage.account_key("anthropic", "safe-id:org"))
        self.assertIsNone(collect(bare, ok, dict(loggedIn=True, email="other@example.com"))["account_email"])
        self.assertIsNone(collect(dict(oauthAccount={}), ok, signed))                # no account record: nothing

    def test_an_account_without_windows_keeps_its_identity_but_never_replaces_known_windows(self):
        bare = usage.normalize_codex_limits(dict(accountId="account", rateLimits={}),
                                            dict(planType="plus", email="owner@example.com"), 5000)
        self.assertEqual((bare["windows"], bare["error"], bare["account_email"], bare["plan"]),
                         ([], usage.NO_WINDOWS, "owner@example.com", "plus"))
        self.assertEqual(bare["account_key"], usage.account_key("openai", "account"))
        usage.validate_usage(dict(tokens=None, limits=bare), "codex")
        with self.assertRaises(ValueError):                         # no identity either: nothing to report
            usage.normalize_codex_limits(dict(rateLimits={}), {}, 5000)
        known = dict(limits("codex"), account_key=bare["account_key"])
        kept = usage.keep_windows(known, bare)                      # the same account: its windows and their time stay
        self.assertEqual((kept["windows"], kept["collected_at"], kept["error"], kept["account_email"]),
                         (known["windows"], 3000, "Account limits could not be refreshed.", "owner@example.com"))
        self.assertEqual(usage.keep_windows(limits("codex"), bare), bare)      # another account: they do not stay
        self.assertEqual(usage.keep_windows(None, bare), bare)
        full = dict(known, collected_at=6000, account_email="owner@example.com")
        self.assertEqual(usage.keep_windows(known, full), full)                # a reading with windows replaces
        collector = usage.Collector(self.kit, "vps", "codex", lambda data: None, self.home)
        collector.data = dict(tokens=tokens("codex"), limits=known)
        with patch("usage.transcript_tokens", return_value=tokens("codex")), patch("usage.codex_limits", return_value=bare):
            collector.collect()
        got = collector.data["limits"]
        self.assertEqual((len(got["windows"]), got["collected_at"], got["account_email"]), (1, 3000, "owner@example.com"))

    def test_a_confirmed_sign_out_clears_the_email_and_a_failed_refresh_keeps_it_with_its_old_time(self):
        """One helper process (one Collector) over several polls: signed in, then a refresh that fails, then signed out."""
        then = time.time() - 30
        record = dict(accountUuid="safe-id", organizationUuid="org", emailAddress="owner@example.com")
        cache = dict(accountUuid="safe-id", fetchedAtMs=then * 1000, utilization=dict(five_hour=dict(utilization=3, resets_at=None)))
        (self.home / ".claude.json").write_text(json.dumps(dict(oauthAccount=record, cachedUsageUtilization=cache)))
        ok, failed = dict(num_turns=0, is_error=False), ValueError("CLI read failed")
        answers = {}

        def run(args, cwd, timeout=25, ok=(0,)):
            answer = answers["status" if args[1:3] == ["auth", "status"] else "usage"]
            if isinstance(answer, Exception):
                raise answer
            return answer

        collector = usage.Collector(self.kit, "manager", "claude", lambda data: None, self.home)

        def poll(status, usage_answer):
            answers.update(status=status, usage=usage_answer)
            collector.last_poll = 0                                  # the next poll is due
            with patch("usage.transcript_tokens", return_value=tokens()), patch("usage.run_json", side_effect=run):
                collector.collect()
            return dict(collector.data["limits"])

        first = poll(dict(loggedIn=True, email="owner@example.com"), ok)
        self.assertEqual((first["account_email"], first["error"]), ("owner@example.com", None))
        self.assertAlmostEqual(first["collected_at"], then, delta=1)
        kept = poll(dict(loggedIn=True, email="owner@example.com"), failed)             # a refresh that fails
        self.assertEqual((kept["account_email"], kept["collected_at"], kept["error"]),
                         ("owner@example.com", first["collected_at"], "Account limits could not be refreshed."))
        kept = poll(failed, failed)                                                    # nothing can be read
        self.assertEqual((kept["account_email"], kept["collected_at"]), ("owner@example.com", first["collected_at"]))
        gone = poll(dict(loggedIn=False, email=None), failed)                          # the runtime says signed out
        self.assertEqual((gone["account_email"], gone["error"], gone["collected_at"], gone["windows"], gone["account_key"]),
                         (None, "CLI sign-in is required.", first["collected_at"], first["windows"], first["account_key"]))
        usage.validate_usage(collector.data, "claude")
        self.assertNotIn("owner@example.com", collector.path.read_text())              # also not in the helper's cache
        still = poll(failed, failed)                                                   # later failures do not bring it back
        self.assertEqual((still["account_email"], still["error"], still["collected_at"]),
                         (None, "CLI sign-in is required.", first["collected_at"]))
        again = poll(dict(loggedIn=True, email="owner@example.com"), failed)           # signed in again, limits unread:
        self.assertEqual((again["account_email"], again["error"]), (None, usage.IDENTITY_CHANGED))    # not confirmed
        back = poll(dict(loggedIn=True, email="owner@example.com"), ok)                # signed in again
        self.assertEqual((back["account_email"], back["error"]), ("owner@example.com", None))
        # The runtime confirms an account, but one without an email (for example an API key), or another account, and
        # the limits cannot be read: the windows stay, but the earlier subscription email is not this identity.
        for status in (dict(loggedIn=True, email=None), dict(loggedIn=True, email="other@example.com")):
            poll(dict(loggedIn=True, email="owner@example.com"), ok)
            changed = poll(status, failed)
            self.assertEqual((changed["account_email"], changed["error"], changed["windows"], changed["collected_at"]),
                             (None, usage.IDENTITY_CHANGED, back["windows"], back["collected_at"]))
            self.assertEqual(changed["account_key"], back["account_key"])               # its history stays as it was
            later = poll(failed, failed)                                                # and it stays "changed"
            self.assertEqual((later["account_email"], later["error"]), (None, usage.IDENTITY_CHANGED))
        poll(dict(loggedIn=True, email="owner@example.com"), ok)
        same = poll(dict(loggedIn=True, email="OWNER@example.com"), failed)             # the same account: it stays
        self.assertEqual(same["account_email"], "owner@example.com")
        # Codex, primary and screen route: the same two cases.
        codex = usage.Collector(self.kit, "seo", "codex", lambda data: None, self.home, screen_command="codex app-server")
        good = dict(limits("codex"), account_key=usage.account_key("openai", "account"), account_email="owner@example.com")
        refresh = "Account limits could not be refreshed."
        for outcome, email, error in ((good, "owner@example.com", None),
                                      (ValueError("account read failed"), "owner@example.com", refresh),
                                      (usage.Unrefreshed("owner@example.com"), "owner@example.com", refresh),
                                      (usage.Unrefreshed(""), None, usage.IDENTITY_CHANGED),      # an API key now
                                      (ValueError("account read failed"), None, usage.IDENTITY_CHANGED),
                                      (good, "owner@example.com", None),
                                      (usage.Unrefreshed("other@example.com"), None, usage.IDENTITY_CHANGED),
                                      (good, "owner@example.com", None),
                                      (usage.SignedOut("no account"), None, "CLI sign-in is required.")):
            codex.last_poll = 0
            answer = dict(return_value=dict(outcome)) if isinstance(outcome, dict) else dict(side_effect=outcome)
            with patch("usage.transcript_tokens", return_value=tokens("codex")), patch("usage.screen_tokens", return_value=None), \
                    patch("usage.codex_limits", **answer):
                codex.collect()
            for reading in (codex.data["limits"], codex.data["screen"]["limits"]):
                self.assertEqual((reading["account_email"], reading["error"], reading["collected_at"]), (email, error, 3000))

    def test_a_codex_runtime_without_an_account_is_signed_out_not_a_failed_read(self):
        fake = self.home / "fake-codex"                 # an app-server stand-in for initialize, the account and the limits
        script = ("#!/usr/bin/env python3\nimport json, sys\nfor line in sys.stdin:\n    m = json.loads(line)\n"
                  "    if m.get('id') == 1:\n        print(json.dumps({'id': 1, 'result': {}}), flush=True)\n"
                  "    if m.get('id') == 2:\n        print(json.dumps({'id': 2, 'result': %s}), flush=True)\n"
                  "    if m.get('id') == 3:\n        print(json.dumps({'id': 3, 'error': {'message': 'no'}}), flush=True)\n")
        fake.write_text(script % "{'account': None, 'requiresOpenaiAuth': True}")
        fake.chmod(0o755)
        with self.assertRaises(usage.SignedOut):                        # the runtime's own answer: no account
            usage.codex_limits(str(self.home), str(fake))
        for account, email in (("{'type': 'chatgpt', 'email': 'owner@example.com'}", "owner@example.com"),
                               ("{'type': 'apiKey'}", "")):              # an API key: an account without an email
            fake.write_text(script % ("{'account': %s}" % account))
            with self.assertRaises(usage.Unrefreshed) as failed:        # the account is known; its limits read fails
                usage.codex_limits(str(self.home), str(fake))
            self.assertEqual(failed.exception.email, email)
        fake.write_text(script % "{}")                                  # no account field at all: nothing is confirmed
        with self.assertRaises(ValueError) as failed:
            usage.codex_limits(str(self.home), str(fake))
        self.assertNotIsInstance(failed.exception, (usage.SignedOut, usage.Unrefreshed))

    def test_provider_timeout_retains_prior_numbers_and_original_time(self):
        collector = usage.Collector(self.kit, "manager", "claude", lambda data: None, self.home)
        collector.data = dict(tokens=tokens(), limits=limits())
        with patch("usage.transcript_tokens", side_effect=ValueError("PRIVATE")), patch("usage.claude_limits", side_effect=ValueError("PRIVATE")):
            collector.collect()
        self.assertEqual(collector.data["tokens"]["total"], 100)
        self.assertEqual(collector.data["tokens"]["collected_at"], 3000)
        self.assertEqual(collector.data["limits"]["collected_at"], 3000)
        self.assertEqual(collector.data["limits"]["windows"][0]["used_percent"], 14.5)
        self.assertNotIn("PRIVATE", collector.path.read_text())

    def test_poll_budget_survives_helper_restart(self):
        collector = usage.Collector(self.kit, "vps", "codex", lambda data: None, self.home)
        with patch("usage.transcript_tokens", return_value=tokens("codex")), patch("usage.codex_limits", return_value=limits("codex")) as fetch:
            collector.collect()
            collector.collect()
            usage.Collector(self.kit, "vps", "codex", lambda data: None, self.home).collect()
        self.assertEqual(fetch.call_count, 1)

    def test_a_sign_in_has_the_next_scan_read_the_account_again(self):
        """The machine signed in to another account, so the one reading the owner's card is made of must not wait
        out the poll budget: until it is taken again, the card names the account he left."""
        collector = usage.Collector(self.kit, "vps", "codex", lambda data: None, self.home)
        with patch("usage.transcript_tokens", return_value=tokens("codex")), patch("usage.codex_limits", return_value=limits("codex")) as fetch:
            collector.collect()
            collector.collect()
            self.assertEqual(fetch.call_count, 1, "the second scan is still inside the poll budget")
            collector.account_again()
            collector.collect()
        self.assertEqual(fetch.call_count, 2)


class UsageAPI(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM["addresses"]["hub"] = "127.0.0.1"

    def test_report_is_read_only_for_task_delivery_and_persists(self):
        eid = hub.emit("manager", "say", "unread")
        payload = dict(tokens=tokens(), limits=limits())
        self.assertEqual(self.request("/helper/usage/manager", payload)[0], 200)
        hub.DB.close()
        self.connect()
        state = self.request()[1]
        payload["limits"]["account_email"] = None                   # this helper sent none: unknown
        self.assertEqual(state["agents"][0]["usage"], payload)
        self.assertIsNone(hub.q1("SELECT read_at FROM events WHERE id=?", (eid,))["read_at"])
        self.assertEqual(self.count("tasks"), 0)

    def test_only_agent_host_can_report_and_owner_can_read(self):
        hub.TEAM["addresses"]["hub"] = "127.0.0.2"
        self.assertEqual(self.request("/helper/usage/manager", dict(tokens=tokens(), limits=limits()))[0], 403)
        self.assertEqual(self.count("agent_usage"), 0)

    def test_rejects_extra_fields_raw_errors_bad_totals_and_duplicate_windows(self):
        payload = dict(tokens=tokens(), limits=limits())
        cases = []
        for key, value in (("access_token", "PRIVATE"), ("error", "PRIVATE"), ("total", 999), ("input", -1)):
            changed = copy.deepcopy(payload)
            changed["tokens"][key] = value
            cases.append(changed)
        changed = copy.deepcopy(payload)
        changed["limits"]["windows"] *= 2
        cases.append(changed)
        for case in cases:
            self.assertEqual(self.request("/helper/usage/manager", case)[0], 400)
        self.assertEqual(self.count("agent_usage"), 0)

    def test_the_owner_gets_the_account_email_and_an_invalid_one_is_refused(self):
        self.assertIn("account_email", self.request()[1]["ui_features"])
        newer = dict(limits(), collected_at=4000, account_email="owner@example.com")
        self.assertEqual(self.request("/helper/usage/manager", dict(tokens=tokens(), limits=newer))[0], 200)
        self.assertEqual(self.request()[1]["agents"][0]["usage"]["limits"]["account_email"], "owner@example.com")
        for bad in ("not-an-email", "a b@example.com", "two@@example.com", 5, "x" * 250 + "@example.com"):
            self.assertEqual(self.request("/helper/usage/manager",
                                          dict(tokens=tokens(), limits=dict(newer, account_email=bad)))[0], 400)
        self.assertEqual(self.request("/helper/usage/manager", dict(                    # it belongs to limits only
            tokens=dict(tokens(), account_email="owner@example.com"), limits=newer))[0], 400)
        bare = dict(newer, collected_at=5000, windows=[], error=usage.NO_WINDOWS)       # an account without windows
        self.assertEqual(self.request("/helper/usage/manager", dict(tokens=tokens(), limits=bare))[0], 200)
        stored = self.request()[1]["agents"][0]["usage"]["limits"]
        self.assertEqual((stored["windows"], stored["error"], stored["account_email"], stored["account_key"]),
                         ([], usage.NO_WINDOWS, "owner@example.com", newer["account_key"]))
        failed = self.request("/helper/usage/manager", dict(tokens=tokens(), limits=None))      # a later failed read
        kept = self.request()[1]["agents"][0]["usage"]["limits"]
        self.assertEqual((failed[0], kept["account_email"], kept["collected_at"]), (200, "owner@example.com", 5000))
        # **A sign-out keeps the name of the account it signed out of.** The helper sends none, so that the address
        # does not stay on that machine's disk; the hub is the owner's own, and the week the agent spent still says
        # whose week it was.
        out = dict(bare, account_email=None, error="CLI sign-in is required.")          # the helper saw a sign-out
        self.assertEqual(self.request("/helper/usage/manager", dict(tokens=tokens(), limits=out))[0], 200)
        gone = self.request()[1]["agents"][0]["usage"]["limits"]
        self.assertEqual((gone["account_email"], gone["error"], gone["collected_at"]),
                         ("owner@example.com", "CLI sign-in is required.", 5000))
        # An account that changed carries no name forward: that reading says this is not that account. Nor does a
        # sign-out of another account take the earlier one's name.
        for reading in (dict(out, error=usage.IDENTITY_CHANGED),
                        dict(out, account_key=usage.account_key("anthropic", "another"))):
            self.request("/helper/usage/manager", dict(tokens=tokens(), limits=reading))
            self.assertIsNone(self.request()[1]["agents"][0]["usage"]["limits"]["account_email"])
        for marked, named in (("CLI sign-in is required.", "owner@example.com"), (usage.IDENTITY_CHANGED, None)):
            back = dict(bare, collected_at=6000)                                          # signed in, then marked
            self.request("/helper/usage/manager", dict(tokens=tokens(), limits=back))
            self.request("/helper/usage/manager", dict(tokens=tokens(), limits=dict(out, collected_at=6000,
                                                                                    error=marked)))    # a helper that
            self.assertEqual(self.request("/helper/usage/manager", dict(tokens=tokens(), limits=None))[0], 200)
            kept = self.request()[1]["agents"][0]["usage"]["limits"]                                   # sends no reading
            self.assertEqual((kept["error"], kept["account_email"]), (marked, named))   # does not turn it into a refresh

    def test_older_failure_cannot_erase_measured_values(self):
        self.request("/helper/usage/manager", dict(tokens=tokens(), limits=limits()))
        self.request("/helper/usage/manager", dict(tokens=None, limits=None))
        data = self.request()[1]["agents"][0]["usage"]
        self.assertEqual(data["tokens"]["total"], 100)
        self.assertEqual(data["limits"]["collected_at"], 3000)
        self.assertIsNotNone(data["limits"]["error"])


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(TokenRecords)
    suite.addTests(UsageAPI(name) for name in UsageAPI.__dict__ if name.startswith("test_"))
    return suite


if __name__ == "__main__":
    unittest.main()

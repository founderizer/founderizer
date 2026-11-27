"""What the work costs (AUTONOMY.md P8, lane L7): each session's four kinds of tokens apart, its kind, model,
runtime, account and window share; the token weights of the runtime facts, which the owner changes through the
settings route; see_history what="costs" for every agent in its own scope; GET /ui/costs and the admin MCP's
see_costs; set_agent_model and model_changes; what each session spent in each 15-minute slot (token_slots) and
GET /ui/costs by=. An in-process hub with a temporary database and git checkout, on the
Claude and the Codex runtime forms; no helper and no AI call.

    python3 -m unittest -v test_costs
"""
import json
from pathlib import Path
import shutil
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

import hub
import lifecycle
import owner_mcp
import usage
from test_chat_apps import git
from test_release_turns import helper_reports
from test_ui_api import OwnerAPI

CLAUDE = "anthropic:" + "a" * 32
OPENAI = "openai:" + "b" * 32
# A lead with a worker, and a Codex worker of the fleet manager's own.
TEAM = {"hub": {"machine": "hub", "port": 8765},
        "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2", "lead-box": "127.0.0.3", "hand-box": "127.0.0.4",
                      "solo-box": "127.0.0.5"},
        "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                   "lead": {"role": "lead", "runtime": "claude", "machine": "lead-box", "can": ["shell"]},
                   "hand": {"role": "worker", "runtime": "claude", "machine": "hand-box", "can": ["shell"],
                            "reports_to": "lead"},
                   "solo": {"role": "worker", "runtime": "codex", "machine": "solo-box", "can": ["shell"]}}}
SOURCE = {"manager": "127.0.0.2", "lead": "127.0.0.3", "hand": "127.0.0.4", "solo": "127.0.0.5"}
DAY = 86400


def session(sid, last, input=100, cache_read=900, cache_write=0, output=50, calls=4, model="claude-opus-5-5",
            first=0.5):
    """One by_session row of a helper with session_kinds."""
    return dict(session_id=sid, total=input + cache_read + cache_write + output, last_activity=last, input=input,
                cache_read=cache_read, cache_write=cache_write, output=output, calls=calls, model=model,
                first_cache_share=first)


def report(rows, runtime="claude", key=CLAUDE, used=40.0, at=None, windows=None):
    """A helper's usage report: its sessions and one reading of its account, a week window first."""
    at = at or time.time()
    total = {k: sum(r["total"] if k == "input" and "input" not in r else r.get(k, 0) for r in rows)
             for k in usage.TOKEN_KEYS}
    tokens = dict(total, total=sum(total.values()), sessions=len(rows), since=None, last_activity=None,
                  collected_at=at, source=usage.SOURCES[runtime], scope=usage.SCOPE, error=None, by_session=rows)
    windows = windows if windows is not None else [
        dict(id="weekly:1", label="7 days", used_percent=used, resets_at=at + 3 * DAY, window_minutes=10080),
        dict(id="session:0", label="5 hours", used_percent=10.0, resets_at=at + 3600, window_minutes=300)]
    limits = dict(collected_at=at, source=usage.LIMIT_SOURCES[runtime], plan="Max", account_key=key,
                  account_email=None, windows=windows, error=None)
    return dict(tokens=tokens, limits=limits)


def load_tests(loader, _tests, _pattern):
    """Only this file's cases, not the inherited OwnerAPI ones."""
    suite = unittest.TestSuite()
    for cls in (Helper, Storing, Weights, Costs, Scope, ModelChanges, Slots):
        suite.addTests(cls(name) for name in cls.__dict__ if name.startswith("test_"))
    return suite


class Helper(unittest.TestCase):
    """usage.py: what a helper with session_kinds reads from its runtime's own records, and what it sends."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name)
        self.kit = str((self.home / "fleet-pilot").resolve())

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, rows):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(x) + "\n" for x in rows))

    def test_a_claude_session_gives_its_four_kinds_its_calls_its_model_and_its_first_call_s_cache_share(self):
        root = self.home / ".claude/projects" / usage.re.sub(r"[^A-Za-z0-9-]", "-", self.kit)

        def row(mid, ts, i, o, r, w, model="claude-opus-5-5", side=False):
            return dict(type="assistant", cwd=self.kit, sessionId="s1", isSidechain=side, timestamp=ts,
                        message=dict(id=mid, model=model, usage=dict(input_tokens=i, output_tokens=o,
                                                                     cache_read_input_tokens=r,
                                                                     cache_creation_input_tokens=w)))
        # the first call writes the cache, the second reads it, and a subagent's call counts in the session at its own
        # model (helper feature session_models), not at the session's
        self.write(root / "s1.jsonl", [row("m1", "2026-10-10T10:00:00Z", 10, 5, 0, 1000),
                                       row("m1", "2026-10-10T10:00:00Z", 10, 9, 0, 1000),      # the same call again
                                       row("m2", "2026-10-10T10:01:00Z", 2, 7, 1000, 30)])
        self.write(root / "s1" / "subagents" / "a.jsonl",
                   [row("m3", "2026-10-10T10:02:00Z", 1, 1, 50, 0, model="claude-haiku-5-5", side=True)])
        data = usage.transcript_tokens("claude", self.kit, self.home)
        self.assertEqual(data["by_session"], [dict(session_id="s1", total=2110, last_activity=data["last_activity"],
                                                   input=13, output=17, cache_read=1050, cache_write=1030, calls=3,
                                                   model="claude-opus-5-5", first_cache_share=0.0,
                                                   models=[["claude-opus-5-5", 12, 1000, 1030, 16, 2],
                                                           ["claude-haiku-5-5", 1, 50, 0, 1, 1]])])
        usage.validate_usage(dict(tokens=data, limits=None), "claude")

    def test_a_codex_session_counts_each_call_once_and_takes_its_model_from_its_turns(self):
        root = self.home / ".codex/sessions"

        def event(i, o, c):
            return dict(type="event_msg", timestamp="2026-10-10T11:00:00Z", payload=dict(type="token_count", info=dict(
                total_token_usage=dict(input_tokens=i, output_tokens=o, cached_input_tokens=c))))
        meta = dict(type="session_meta", payload=dict(id="id1", cwd=self.kit))
        turn = dict(type="turn_context", timestamp="2026-10-10T11:00:00Z", payload=dict(model="gpt-6.1-sol"))
        self.write(root / "a.jsonl", [meta, turn, event(100, 5, 80), event(300, 20, 200), event(300, 20, 200)])
        self.write(root / "copy.jsonl", [meta, event(300, 20, 200)])           # a copy of the same session
        data = usage.transcript_tokens("codex", self.kit, self.home)
        self.assertEqual({k: data["by_session"][0][k] for k in usage.SESSION_KINDS},
                         dict(input=100, cache_read=200, cache_write=0, output=20, calls=2, model="gpt-6.1-sol",
                              first_cache_share=0.8))
        self.assertEqual(data["by_session"][0]["models"], [["gpt-6.1-sol", 100, 200, 0, 20, 2]])
        usage.validate_usage(dict(tokens=data, limits=None), "codex")

    def test_a_report_takes_each_session_in_one_of_two_shapes_and_nothing_between(self):
        good = report([session("s1", 1000.0)])
        usage.validate_usage(good, "claude")
        usage.validate_usage(usage.plain_sessions(good), "claude")
        for change in (dict(model="bad model!"), dict(first_cache_share=1.5), dict(calls=-1), dict(input=101),
                       dict(calls=2.5)):
            bad = report([dict(session("s1", 1000.0), **change)])
            if "input" in change:
                bad["tokens"]["by_session"][0]["total"] -= 0       # the total no longer adds up
            with self.assertRaises(ValueError, msg=change):
                usage.validate_usage(bad, "claude")
        half = report([session("s1", 1000.0)])
        del half["tokens"]["by_session"][0]["model"]
        with self.assertRaises(ValueError):
            usage.validate_usage(half, "claude")

    def test_the_kinds_go_only_to_a_hub_that_said_it_takes_them(self):
        """Helper feature session_kinds: a release from before it refuses a report with them, so the helper sends
        them only after the hub's answer said it takes them, and sends the same report without them at once when a
        hub refuses it (a rollback)."""
        sent, answers = [], []

        def publish(data):
            sent.append("calls" in data["tokens"]["by_session"][0])
            return answers.pop(0)
        collector = usage.Collector(self.kit, "hand", "claude", publish, self.home)
        data = report([session("s1", 1000.0)])
        answers[:] = [(200, {"ok": True, "session_kinds": True})]
        collector.send(data)                                   # the first report: plain, the hub says it takes them
        answers[:] = [(200, {"ok": True, "session_kinds": True})]
        collector.send(data)                                   # so the next one carries them
        answers[:] = [(400, {"error": "invalid usage report"}), (200, {"ok": True})]
        collector.send(data)                                   # a hub from before them: plain again, at once
        answers[:] = [(200, {"ok": True})]
        collector.send(data)                                   # and it stays plain
        self.assertEqual(sent, [False, True, True, False, False])
        self.assertIn("session_kinds", lifecycle.FEATURES)

    def test_past_eight_models_the_smallest_fold_into_one_of_no_model(self):
        """A report keeps a session's models within MODELS_MAX: the smallest are one entry of no model, which the hub
        prices at its runtime's default, and the session's own totals stay what they were."""
        models = {f"claude-m{n}": [n * 10, 0, 0, n, n] for n in range(1, 12)}
        models[None] = [5, 0, 0, 0, 1]
        rows = usage.model_rows(models)
        self.assertEqual(([r[0] for r in rows], rows[-1]),
                         ([f"claude-m{n}" for n in range(11, 4, -1)] + [None], [None, 105, 0, 0, 10, 11]))
        usage.validate_models(dict(zip(usage.MODEL_FIELDS, map(sum, zip(*models.values()))), models=rows))

    def test_each_model_goes_only_to_a_hub_that_said_it_takes_them(self):
        """Helper feature session_models: the release before refuses a session with its models, so they go only
        after the hub's answer said it takes them; a hub that refuses them gets each session's kinds at once. A report
        that the models would take past the hub's size limit goes with the kinds only."""
        sent, answers = [], []

        def publish(data):
            row = data["tokens"]["by_session"][0]
            sent.append("models" if "models" in row else "kinds" if "calls" in row else "plain")
            return answers.pop(0)
        collector = usage.Collector(self.kit, "hand", "claude", publish, self.home)
        data = report([dict(session("s1", 1000.0), models=[["claude-opus-5-5", 60, 900, 0, 40, 3],
                                                           ["claude-haiku-5-5", 40, 0, 0, 10, 1]])])
        usage.validate_usage(data, "claude")
        both, kinds = {"ok": True, "session_kinds": True, "session_models": True}, {"ok": True, "session_kinds": True}
        for answer in ([(200, both)], [(200, both)], [(400, {"error": "invalid usage report"}), (200, kinds)],
                       [(200, kinds)], [(200, both)]):
            answers[:] = answer
            collector.send(data)
        answers[:] = [(200, both)]
        with patch("usage.REPORT_MAX", 100):
            collector.send(data)
        self.assertEqual(sent, ["plain", "models", "models", "kinds", "kinds", "kinds", "kinds"])
        self.assertIn("session_models", lifecycle.FEATURES)


class Base(OwnerAPI):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="fleet-costs-"))
        self.addCleanup(shutil.rmtree, str(self.root), True)
        seed = self.root / "seed"
        seed.mkdir()
        (seed / "team.json").write_text(json.dumps(TEAM, indent=2) + "\n")
        git("init", "-q", str(seed))
        git("add", "-A", cwd=seed)
        git("commit", "-q", "-m", "seed", cwd=seed)
        git("clone", "-q", "--bare", str(seed), str(self.root / "origin.git"))
        git("clone", "-q", str(self.root / "origin.git"), str(self.root / "kit"))
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = json.loads(json.dumps(TEAM))
        hub.CFG["team_path"] = str(self.root / "kit" / "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        self.t0 = time.time()

    def origin_team(self):
        return json.loads(git("--git-dir", str(self.root / "origin.git"), "show", "main:team.json"))

    def usage(self, agent, rows, **kw):
        code, answer = self.request(f"/helper/usage/{agent}",
                                    report(rows, runtime=TEAM["agents"][agent]["runtime"], **kw), source=SOURCE[agent])
        self.assertEqual(code, 200, answer)
        return answer

    def stored(self, agent, sid):
        return hub.q1("SELECT * FROM session_tokens WHERE agent=? AND session_id=?", (agent, sid))

    def new_task(self, owner, title="Answer the tickets", **extra):
        fields = dict({"title": title, "details": "", "done_when": "each ticket has a draft", "needs": "none",
                       "owner": owner, "requester": hub.reports_to(owner), "state": "working", "created": self.t0,
                       "last_activity": self.t0, "attempt": 1}, **extra)
        return hub.ins(f"INSERT INTO tasks({','.join(fields)}) VALUES({','.join('?' * len(fields))})",
                       tuple(fields.values()))

    def link(self, task_id, sid, runtime="claude"):
        """The task's thread records name its session, as the helper's thread reader sends them."""
        hub.ins("INSERT INTO thread_events(task,attempt,session,seq,ts,type,data,created) VALUES(?,1,?,1,?,"
                "'session',?,?)", (task_id, str(uuid.uuid4()), self.t0,
                                   json.dumps({"runtime": runtime, "session_id": sid}), self.t0))

    def duty(self, agent, text="Answer every new ticket. It drafts a reply."):
        return hub.ins("INSERT INTO responsibilities(agent,text,state,revision,created,updated,created_by,request_id) "
                       "VALUES(?,?,'active',1,?,?,'manager',?)", (agent, text, self.t0, self.t0, str(uuid.uuid4())))

    def case(self, duty, key, opened, repeated=0):
        return hub.ins("INSERT INTO duty_cases(responsibility,key,title,source,state,opened,by,repeated) "
                       "VALUES(?,?,'A ticket','watch','closed',?,'hub',?)", (duty, key, opened, repeated))

    def tool(self, who, name, task=None, **args):
        """One tool call: the manager in its standing session, any other agent in its task's session."""
        if hub.role_of(who) == "manager":
            return hub.call_tool(who, name, args)
        tid = task or self.new_task(who, title="Look at the costs")
        return hub.call_tool(who, name, dict(args, task_id=hub.tref(tid)), ("test-generation", hub.tref(tid), 1))

    def ok(self, who, name, **args):
        text, err = self.tool(who, name, **args)
        self.assertFalse(err, text)
        return text

    def refused(self, who, name, **args):
        text, err = self.tool(who, name, **args)
        self.assertTrue(err, text)
        return text


class Storing(Base):
    """The four kinds are stored apart, with what the hub adds to them."""

    def test_the_four_kinds_are_stored_apart_and_a_plain_report_keeps_them(self):
        answer = self.usage("hand", [session("s1", self.t0 - 60, input=120, cache_read=880, cache_write=30,
                                             output=70, calls=6, first=0.25)])
        self.assertTrue(answer["session_kinds"])
        row = self.stored("hand", "s1")
        self.assertEqual({k: row[k] for k in ("input", "cache_read", "cache_write", "output", "calls", "model",
                                              "first_cache_share", "runtime", "account", "total")},
                         dict(input=120, cache_read=880, cache_write=30, output=70, calls=6, model="claude-opus-5-5",
                              first_cache_share=0.25, runtime="claude", account=CLAUDE, total=1100))
        # an older helper, or this one after a rollback, sends totals only: what is stored stays
        plain = usage.plain_sessions(report([session("s1", self.t0 - 30, input=120, cache_read=980, cache_write=30,
                                                     output=70)]))
        self.assertEqual(self.request("/helper/usage/hand", plain, source=SOURCE["hand"])[0], 200)
        row = self.stored("hand", "s1")
        self.assertEqual((row["total"], row["input"], row["calls"], row["model"]), (1200, 120, 6, "claude-opus-5-5"))

    def test_a_session_takes_its_kind_from_its_task_and_a_standing_one_is_matched_again(self):
        duty = self.duty("hand")
        kinds = {"case": self.new_task("hand", responsibility=duty, duty_case=self.case(duty, "ticket-1", self.t0)),
                 "wake": self.new_task("hand", trigger_id=7),
                 "goal": self.new_task("hand", goal_id=3),
                 "task": self.new_task("hand")}
        for name, tid in kinds.items():
            self.link(tid, f"s-{name}")
        self.usage("hand", [session(f"s-{name}", self.t0 - 60) for name in kinds] + [session("s-late", self.t0 - 60)])
        got = {sid: (r["kind"], r["task_kind"]) for sid, r in
               ((r["session_id"], r) for r in hub.q("SELECT * FROM session_tokens WHERE agent='hand'"))}
        self.assertEqual(got, {"s-case": ("case", f"R-{duty}"), "s-wake": ("wake", "trigger 7"),
                               "s-goal": ("task", "G-3"), "s-task": ("task", "task"), "s-late": ("standing", None)})
        # the thread records of s-late's task arrive after the usage report: it is matched at the next one
        self.link(self.new_task("hand"), "s-late")
        self.usage("hand", [session("s-late", self.t0 - 30)])
        self.assertEqual((self.stored("hand", "s-late")["kind"], self.stored("hand", "s-late")["task_kind"]),
                         ("task", "task"))
        # a task of another agent that names the same session id is not this agent's
        self.link(self.new_task("solo"), "s-solo")
        self.usage("hand", [session("s-solo", self.t0 - 30)])
        self.assertEqual(self.stored("hand", "s-solo")["kind"], "standing")

    def test_a_session_keeps_the_runtime_and_the_account_it_spent_on(self):
        self.usage("solo", [session("c1", self.t0 - 60, model="gpt-6.1-sol")], key=OPENAI)
        self.assertEqual((self.stored("solo", "c1")["runtime"], self.stored("solo", "c1")["account"]),
                         ("codex", OPENAI))
        other = "openai:" + "c" * 32
        # the machine signs in to another account: a session that spends now is that account's, an old one is not
        self.usage("solo", [session("c1", self.t0 - 60, model="gpt-6.1-sol"),
                            session("c2", self.t0 - 10, model="gpt-6.1-sol")], key=other)
        self.assertEqual(self.stored("solo", "c1")["account"], OPENAI)
        self.assertEqual(self.stored("solo", "c2")["account"], other)
        # the runtime before a switch: its sessions are priced as its own, never as the new runtime's
        data = report([session("c3", self.t0 - 10, model="gpt-6.1-sol")], runtime="codex", key=other)
        previous = report([session("old-claude", self.t0 - 5 * DAY)])["tokens"]
        hub.TEAM["agents"]["solo"]["runtime_policies"] = {"claude": {"start": "claude --permission-mode dontAsk {settings} {prompt}"}}
        data["previous"] = {"runtime": "claude", "tokens": previous}
        self.assertEqual(self.request("/helper/usage/solo", data, source=SOURCE["solo"])[0], 200)
        self.assertEqual((self.stored("solo", "old-claude")["runtime"], self.stored("solo", "old-claude")["account"]),
                         ("claude", None))

    def test_the_window_shares_of_one_window_add_up_to_its_used_percent(self):
        """Decision 33: the points are the window's used percent, split by list dollars over the fleet's sessions in
        it; the shares of a window add up to it, and a session before the window keeps what it had."""
        self.usage("lead", [session("l1", self.t0 - 60, input=1000, cache_read=0, output=0),
                            session("old", self.t0 - 10 * DAY, input=1000, cache_read=0, output=0)], used=30.0)
        self.usage("hand", [session("h1", self.t0 - 60, input=3000, cache_read=0, output=0)], used=40.0)
        self.usage("lead", [session("l1", self.t0 - 60, input=1000, cache_read=0, output=0)], used=40.0)
        shares = {r["session_id"]: r["window_share"] for r in hub.q("SELECT * FROM session_tokens")}
        self.assertEqual((shares["l1"], shares["h1"], shares["old"]), (10.0, 30.0, None))
        # a stale reading, a reading that is not clean, and a window that has reset since change nothing
        for kw in (dict(at=self.t0 - 3600), dict(windows=[]),
                   dict(windows=[dict(id="w", label="7 days", used_percent=99.0, resets_at=self.t0 - 5,
                                      window_minutes=10080)])):
            self.usage("hand", [session("h1", self.t0 - 60, input=3000, cache_read=0, output=0)], **kw)
            self.assertEqual(self.stored("hand", "h1")["window_share"], 30.0, kw)
        # a model's own share of the account is not the account's window: the whole account's week is
        windows = [dict(id="m", label="7 days (Fable)", used_percent=90.0, resets_at=self.t0 + DAY, window_minutes=10080),
                   dict(id="w", label="7 days", used_percent=60.0, resets_at=self.t0 + DAY, window_minutes=10080)]
        self.assertEqual(hub.main_window(report([], windows=windows)["limits"], self.t0)["label"], "7 days")

    def test_each_model_of_a_session_is_kept_and_priced_at_its_own_weights(self):
        """A workflow agent often runs another model than its session: a helper with session_models reports each
        model's tokens, and the hub prices each at its own weights, in the costs and in the window shares. A session
        of an older helper is priced at its own model, as before."""
        mixed = dict(session("mixed", self.t0 - 60, input=2_000_000, cache_read=0, output=0, calls=12),
                     models=[["claude-opus-5-5", 1_000_000, 0, 0, 0, 3], ["claude-haiku-5-5", 1_000_000, 0, 0, 0, 9]])
        answer = self.usage("hand", [mixed, session("opus", self.t0 - 60, input=1_000_000, cache_read=0, output=0)],
                            used=81.0)
        self.assertTrue(answer["session_models"])
        self.assertEqual(json.loads(self.stored("hand", "mixed")["models"]), mixed["models"])
        self.assertAlmostEqual(hub.session_cost(self.stored("hand", "mixed"), hub.price_book()), 4.0 + 0.1)
        shares = {r["session_id"]: r["window_share"] for r in hub.q("SELECT * FROM session_tokens")}
        self.assertEqual((shares["mixed"], shares["opus"]), (41.0, 40.0))
        self.assertAlmostEqual(hub.costs_view(["hand"], self.t0 - 30 * DAY, self.t0)["agents"][0]["now"]["cost"], 8.1)
        # a report without them (an older helper, or a hub that refused them) leaves them while the totals stand
        plain = {k: v for k, v in mixed.items() if k != "models"}
        self.usage("hand", [plain], used=81.0)
        self.assertAlmostEqual(hub.session_cost(self.stored("hand", "mixed"), hub.price_book()), 4.1)
        # and a session that spent since without them is priced at its own model again
        self.usage("hand", [dict(plain, input=3_000_000, total=3_000_000)], used=81.0)
        self.assertAlmostEqual(hub.session_cost(self.stored("hand", "mixed"), hub.price_book()), 12.0)

    def test_the_tokens_of_what_each_agent_did_count_each_session_once(self):
        """see_history what="agents" (history_agents): a helper reports its newest sessions again every 30 seconds,
        so a session counts once, in the window of its last activity, and an old one that is reported again counts
        in no later window."""
        rows = [session("now", self.t0 - 60, input=1000, cache_read=0, output=50),
                session("old", self.t0 - 40 * DAY, input=7000, cache_read=0, output=0)]
        self.usage("hand", rows)
        self.usage("hand", rows)                                # the same sessions, reported again
        said = self.ok("manager", "see_history", what="agents", agent="hand")
        self.assertIn("; 1,050 tokens reported", said)
        self.assertNotIn("8,050", said)
        self.assertNotIn("2,100", said)

    def test_a_report_of_five_hundred_sessions_with_their_kinds_is_taken(self):
        rows = [session(str(uuid.uuid4()), self.t0 - n, model="claude-sonnet-5-5[1m]") for n in range(usage.BY_SESSION)]
        data = report(rows)
        data["previous"] = None
        data.pop("previous")
        self.assertGreater(len(json.dumps(data)), 32768)
        self.usage("hand", rows)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM session_tokens WHERE calls IS NOT NULL")["n"], 500)


class Weights(Base):
    """The weights come from the runtime facts, and the owner changes a fact through the settings route."""

    def settings(self, **body):
        return self.request("/ui/settings", dict(request_id=str(uuid.uuid4()), db="test-generation", **body))

    def test_the_weights_come_from_the_runtime_facts_of_the_session_s_runtime_and_model(self):
        book = hub.price_book()
        self.assertEqual(book["claude"], lifecycle.RUNTIMES["claude"]["token_weights"])
        row = dict(runtime="claude", model="claude-sonnet-5-5", input=1_000_000, cache_read=1_000_000,
                   cache_write=1_000_000, output=1_000_000)
        self.assertAlmostEqual(hub.session_cost(row, book), 2.0 + 0.2 + 4.0 + 10.0)
        self.assertAlmostEqual(hub.session_cost(dict(row, model="claude-opus-5-5[1m]"), book), 4.0 + 0.2 + 8.0 + 20.0)
        self.assertAlmostEqual(hub.session_cost(dict(row, model="claude-unknown-9"), book), 32.2)     # the default
        self.assertAlmostEqual(hub.session_cost(dict(row, runtime="codex", model="gpt-6.1-sol"), book), 14.1)
        self.assertIsNone(hub.session_cost(dict(row, runtime="gemini"), book))          # no prices: no cost
        # The two ACP programs take their prices from the price file of the checkout (lifecycle.price_file): a model
        # of the owner's own server costs nothing, whatever its name holds, and a priced one its price
        prices = lifecycle.RUNTIMES["opencode"]["token_weights"]
        self.assertEqual(book["opencode"], prices)
        self.assertEqual(book["grok"], prices)
        self.assertEqual(hub.session_cost(dict(row, runtime="opencode", model="own/deepseek-r1"), book), 0)
        self.assertAlmostEqual(hub.session_cost(dict(row, runtime="grok", model="grok-4.7"), book),
                               sum(prices["grok"].values()))
        self.assertIsNone(hub.session_cost(dict(row, input=None), book))                # no kinds: no cost
        self.assertEqual(set(hub.EDITABLE_FACTS), {"cache_seconds", "compact_tokens", "token_weights", "routine",
                                                   "default_model"})

    def test_each_model_of_a_session_is_priced_at_its_own_weights(self):
        """Helper feature session_models: a session's own model and its agents' each at their own weights, while they
        add up to the session's four kinds; else, as for an older helper, all of it at the session's own model."""
        book = hub.price_book()
        row = dict(runtime="claude", model="claude-opus-5-5", input=2_000_000, cache_read=1_000_000, cache_write=0,
                   output=1_000_000, models=json.dumps([["claude-opus-5-5", 1_000_000, 0, 0, 1_000_000, 4],
                                                        ["claude-haiku-5-5", 1_000_000, 1_000_000, 0, 0, 7]]))
        self.assertAlmostEqual(hub.session_cost(row, book), (4.0 + 20.0) + (0.1 + 0.01))
        self.assertAlmostEqual(hub.session_cost(dict(row, models=None), book), 2 * 4.0 + 0.2 + 20.0)
        self.assertAlmostEqual(hub.session_cost(dict(row, output=2_000_000), book), 2 * 4.0 + 0.2 + 40.0)
        self.assertAlmostEqual(hub.session_cost(dict(row, runtime="codex"), book), 2 * 2.0 + 0.1 + 10.0)
        self.assertIsNone(hub.session_cost(dict(row, runtime="gemini"), book))          # a name with no prices

    def test_the_owner_changes_a_price_and_a_cache_fact_and_puts_them_back(self):
        code, page = self.request("/ui/settings?db=test-generation")
        self.assertEqual(code, 200, page)
        self.assertEqual(page["runtime_facts"]["codex"]["token_weights"],
                         {"value": lifecycle.RUNTIMES["codex"]["token_weights"],
                          "default": lifecycle.RUNTIMES["codex"]["token_weights"], "set": False})
        self.assertTrue(page["settings"]["model_changes"]["value"])
        price = {"default": {"input": 3.0, "cache_read": 0.3, "cache_write": 3.0, "output": 12.0},
                 "mini": {"input": 0.5, "cache_read": 0.05, "cache_write": 0.5, "output": 2.0}}
        code, receipt = self.settings(runtime_facts={"codex": {"token_weights": price, "cache_seconds": 600}})
        self.assertEqual((code, sorted(receipt["changed"])), (200, ["codex.cache_seconds", "codex.token_weights"]),
                         receipt)
        self.assertEqual(self.origin_team()["runtime_facts"], {"codex": {"token_weights": price,
                                                                         "cache_seconds": 600}})
        self.assertEqual(lifecycle.facts_now(hub.TEAM, "codex")["token_weights"], price)       # applied at once
        self.assertEqual(lifecycle.facts_now(hub.TEAM, "codex")["cache_seconds"], 600)
        self.assertEqual(receipt["runtime_facts"]["codex"]["token_weights"]["set"], True)
        row = dict(runtime="codex", model="gpt-6.1-sol-mini", input=1_000_000, cache_read=0, cache_write=0,
                   output=0)
        self.assertAlmostEqual(hub.session_cost(row, hub.price_book()), 0.5)
        self.assertEqual(self.settings(runtime_facts={"codex": {"cache_seconds": 600}})[1]["changed"], [])
        code, receipt = self.settings(runtime_facts={"codex": {"token_weights": None, "cache_seconds": None}},
                                      settings={"model_changes": False})
        self.assertEqual((code, sorted(receipt["changed"])),
                         (200, ["codex.cache_seconds", "codex.token_weights", "model_changes"]), receipt)
        self.assertNotIn("runtime_facts", self.origin_team())
        self.assertEqual(lifecycle.facts_now(hub.TEAM, "codex")["token_weights"],
                         lifecycle.RUNTIMES["codex"]["token_weights"])
        for facts, why in (({"codex": {"token_weights": {"default": {"input": 1}}}}, "a price without its kinds"),
                           ({"codex": {"token_weights": {"default": dict(price["default"], input=-1)}}}, "below 0"),
                           ({"codex": {"cache_seconds": "300"}}, "not a number"), ({"codex": {"color": 1}}, "no fact"),
                           ({"gemini": {"cache_seconds": 5}}, "no runtime"), ({"codex": {}}, "nothing"), ([], "a list")):
            self.assertEqual(self.settings(runtime_facts=facts)[0], 400, why)

    def test_the_one_changer_reads_each_runtime_s_routine_model_and_the_owner_s_own_wins(self):
        """Plan P9.7: the model and effort of routine work, for each runtime of the agents that the view shows, in the
        line that names set_agent_model; a value the owner sets for it is the one read."""
        view = hub.costs_view(["lead", "hand", "solo"], self.t0 - 30 * DAY, self.t0)
        self.assertEqual(view["routine"], {"claude": lifecycle.RUNTIMES["claude"]["routine"],
                                           "codex": lifecycle.RUNTIMES["codex"]["routine"]})
        said = "\n".join(hub.costs_text(view, 30, "manager"))
        self.assertIn("set_agent_model changes the model or effort of an agent you give work to, inside its own "
                      "account. For routine work the runtime facts give: claude sonnet, low; codex its default "
                      "model, low.", said)
        mini = {"model": "gpt-6.1-sol-mini", "effort": "minimal"}
        code, receipt = self.settings(runtime_facts={"codex": {"routine": mini}})
        self.assertEqual((code, receipt["changed"]), (200, ["codex.routine"]), receipt)
        self.assertEqual(receipt["runtime_facts"]["codex"]["routine"], {"value": mini, "set": True,
                                                                       "default": lifecycle.RUNTIMES["codex"]["routine"]})
        said = "\n".join(hub.costs_text(hub.costs_view(["solo"], self.t0 - DAY, self.t0), 1, "manager"))
        self.assertIn("For routine work the runtime facts give: codex gpt-6.1-sol-mini, minimal.", said)
        self.assertNotIn("For routine work", "\n".join(hub.costs_text(hub.costs_view(["solo"], self.t0 - DAY,
                                                                                     self.t0), 1, "solo")))
        for bad in ({"model": "gpt-6.1-sol-mini"}, {"model": "two words", "effort": "low"}, {"model": None, "effort": 5},
                    "low"):
            self.assertEqual(self.settings(runtime_facts={"codex": {"routine": bad}})[0], 400, bad)

    def test_team_json_checks_the_facts_it_knows_and_keeps_a_later_release_s(self):
        team = json.loads(json.dumps(hub.TEAM))
        for bad in ({"claude": {"cache_seconds": -1}}, {"claude": "fast"}, ["claude"],
                    {"claude": {"token_weights": {"default": {"input": True, "cache_read": 0, "cache_write": 0,
                                                              "output": 0}}}}):
            with self.assertRaises(ValueError, msg=bad):
                hub.validate_team(dict(team, runtime_facts=bad))
        later = {"claude": {"closed_version": "2.1.311"}, "gemini": {"cache_seconds": 30}}
        hub.validate_team(dict(team, runtime_facts=later))
        hub.commit_kit_file("team.json", (json.dumps(dict(self.origin_team(), runtime_facts=later), indent=2)
                                          + "\n").encode(), "a later release")
        code, receipt = self.settings(runtime_facts={"claude": {"cache_seconds": 300}})
        self.assertEqual(code, 200, receipt)
        self.assertEqual(self.origin_team()["runtime_facts"],
                         {"claude": {"closed_version": "2.1.311", "cache_seconds": 300}, "gemini": {"cache_seconds": 30}})
        # a value written by hand that its check refuses reads as the table's, and the hub says so
        hub.TEAM["runtime_facts"] = {"claude": {"cache_seconds": "an hour"}}
        self.assertEqual(lifecycle.facts_now(hub.TEAM, "claude")["cache_seconds"],
                         lifecycle.runtime_fact("claude", "cache_seconds"))
        self.assertIn("runtime_facts claude cache_seconds", hub.team_problem(hub.TEAM))

    def test_the_admin_mcp_sends_the_runtime_facts_and_reads_the_costs(self):
        sent = []
        with patch.object(owner_mcp, "command", lambda route, body, what, rid=None: sent.append((route, body))):
            owner_mcp.TOOLS.update({t["name"]: t for t in owner_mcp.tools()})
            owner_mcp.TOOLS["save_settings"]["run"]({"runtime_facts": {"codex": {"cache_seconds": 300}}})
        self.assertEqual(sent, [("/ui/settings", {"runtime_facts": {"codex": {"cache_seconds": 300}}})])
        asked = []
        with patch.object(owner_mcp, "get", lambda route, what, **query: asked.append((route, query)) or
                          type("A", (), {"data": {}})()):
            owner_mcp.costs({"from": "2026-10-01", "agent": "hand", "by": "day,model"})
        self.assertEqual(asked, [("/ui/costs", {"from": "2026-10-01", "to": None, "agent": "hand", "minimum": None,
                                                "by": "day,model"})])


class Costs(Base):
    """see_history what="costs" and GET /ui/costs: a period against the last, per task kind, judged by rework."""

    def work(self, agent, sid, task, last, delivered=None, cost_input=1_000_000, **extra):
        """One session of a task, and the task's result when it was delivered."""
        tid = self.new_task(agent, task=None, **extra) if task is None else task
        if delivered:
            hub.q("UPDATE tasks SET state='completed', outcome='completed', delivered=? WHERE id=?", (delivered, tid))
        self.link(tid, sid)
        return tid

    def test_a_period_compares_with_the_last_per_task_kind_with_a_minimum_count(self):
        duty = self.duty("hand")
        rows, n = [], 0
        for days_ago, count, size in ((5, 4, 1_000_000), (35, 3, 2_000_000)):
            for _ in range(count):
                n += 1
                tid = self.new_task("hand", responsibility=duty, duty_case=self.case(duty, f"k{n}", self.t0 - days_ago * DAY))
                hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.t0 - days_ago * DAY, tid))
                self.link(tid, f"s{n}")
                rows.append(session(f"s{n}", self.t0 - days_ago * DAY, input=size, cache_read=0, output=0, calls=5))
        lone = self.new_task("hand", goal_id=4)               # one result of a goal: too few to compare
        hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.t0 - DAY, lone))
        self.link(lone, "lone")
        rows.append(session("lone", self.t0 - DAY, input=500_000, cache_read=0, output=0))
        self.usage("hand", rows)
        view = hub.costs_view(["hand"], self.t0 - 30 * DAY, self.t0)
        kinds = {(k["kind"], k["task_kind"]): k for k in view["agents"][0]["kinds"]}
        case = kinds[("case", f"R-{duty}")]
        self.assertTrue(case["compared"])
        self.assertEqual((case["now"]["results"], case["now"]["clean"], case["before"]["results"]), (4, 4, 3))
        self.assertAlmostEqual(case["now"]["cost_per_clean"], 4.0)            # 1M input at Opus's $4
        self.assertAlmostEqual(case["before"]["cost_per_clean"], 8.0)
        self.assertFalse(kinds[("task", "G-4")]["compared"])
        self.assertEqual(view["agents"][0]["now"]["calls"], 4 * 5 + 4)
        text = self.ok("hand", "see_history", what="costs")
        self.assertIn(f"cases of R-{duty}: $16.00 ($24.00 before) in 4 sessions", text)
        self.assertIn("4 results, 4 without rework (3 of 3 before)", text)
        self.assertIn("$4.00 ($8.00 before) a clean result", text)
        self.assertIn("tasks of goal G-4: $2.00 (none before) in 1 session; 1 result, 1 without rework (0 of 0 before); "
                      "fewer than 3 results in a period, so not compared", text)
        self.assertIn("at the list prices of the runtime facts now", text)
        self.assertIn("On a subscription account a list price is a weight, not money spent", text)

    def test_rework_is_follow_ups_case_keys_that_come_back_and_corrections_by_staff(self):
        duty = self.duty("hand")                    # lane L2's tasks.source_conversation is in the schema since its push
        done = []
        for key in ("a", "b", "c", "d"):
            tid = self.new_task("hand", responsibility=duty, duty_case=self.case(duty, key, self.t0 - 3 * DAY))
            hub.q("UPDATE tasks SET state='completed', delivered=? WHERE id=?", (self.t0 - 3 * DAY, tid))
            done.append(tid)
        self.new_task("hand", follows=done[0])                                   # a fix of the first
        self.case(duty, "b", self.t0 - DAY, repeated=1)                          # the second's key came back
        self.new_task("hand", follows=done[2], source_conversation=5)            # a person corrected the third
        new = hub.costs_kinds("hand", self.t0 - 30 * DAY, self.t0, hub.price_book())[("case", f"R-{duty}")]
        self.assertEqual({k: new[k] for k in ("results", "clean", "follow_ups", "repeats", "corrections")},
                         dict(results=4, clean=1, follow_ups=1, repeats=1, corrections=1))
        text = "\n".join(hub.costs_text(hub.costs_view(["hand"], self.t0 - 30 * DAY, self.t0), 30, "lead"))
        self.assertIn("rework: 1 follow-up, 1 key back, 1 correction by staff", text)

    def test_a_check_s_quiet_runs_stand_against_its_wakes(self):
        rule = hub.ins("INSERT INTO triggers(agent,state,revision,schedule,task,late_minutes,max_tasks_per_day,anchor,"
                       "created,updated,request_id,created_by) VALUES('solo','active',1,'{}','{}',5,10,?,?,?,'r','solo')",
                       (self.t0, self.t0, self.t0))
        wake = self.new_task("solo", trigger_id=rule)
        fix = self.new_task("solo", title="Fix the check", trigger_id=rule)
        self.link(wake, "w1")
        # lane L4's states: a run that started a wake, one whose new lines joined that open wake, quiet runs, a
        # failure, and the third failure in a row, which wakes the agent once with a task of its own; a run that
        # waits behind a usage limit has not finished
        for state, task, at in (("started", wake, self.t0 - DAY), ("joined", wake, self.t0 - DAY + 60),
                                ("quiet", None, self.t0 - DAY - 60), ("quiet", None, self.t0 - 2 * DAY),
                                ("error", None, self.t0 - DAY - 120), ("error", fix, self.t0 - DAY - 180),
                                ("quiet", None, self.t0 - 40 * DAY), ("waiting", None, None)):
            hub.ins("INSERT INTO trigger_runs(trigger_id,revision,due,state,task,created,finished) VALUES(?,1,?,?,?,?,?)",
                    (rule, at or self.t0, state, task, at or self.t0, at))
        self.usage("solo", [session("w1", self.t0 - DAY, input=100_000, cache_read=0, output=0, model="gpt-6.1-sol")],
                   key=OPENAI)
        check = hub.costs_view(["solo"], self.t0 - 30 * DAY, self.t0)["checks"][0]
        self.assertEqual(check["now"], {"wakes": 1, "joined": 1, "quiet": 2, "failed": 2, "cost": 0.2})
        self.assertEqual((check["before"]["quiet"], check["before"]["wakes"]), (1, 0))
        text = self.ok("solo", "see_history")
        self.assertIn(f"check {rule} of solo: 1 wakes (0 before), 1 runs added lines to an open wake (0), 2 quiet "
                      f"runs (1), 2 failed (0); its wakes cost $0.20 (none before)", text)
        # lane L4's count of a series of quiet runs that folds into one row (NULL is one run; its release adds it)
        if "runs" not in {c["name"] for c in hub.q("PRAGMA table_info(trigger_runs)")}:
            hub.DB.execute("ALTER TABLE trigger_runs ADD COLUMN runs INTEGER")
        hub.q("UPDATE trigger_runs SET runs=12 WHERE state='quiet' AND finished>?", (self.t0 - 1.5 * DAY,))
        self.assertEqual(hub.costs_view(["solo"], self.t0 - 30 * DAY, self.t0)["checks"][0]["now"]["quiet"], 13)

    def test_an_account_shows_each_window_what_is_left_and_who_used_its_main_window(self):
        self.usage("lead", [session("l1", self.t0 - 60, input=1000, cache_read=0, output=0)], used=62.0)
        self.usage("hand", [session("h1", self.t0 - 60, input=3000, cache_read=0, output=0)], used=62.0)
        self.usage("lead", [session("l1", self.t0 - 60, input=1000, cache_read=0, output=0)], used=62.0)
        account = hub.costs_view(["lead", "hand"], self.t0 - 30 * DAY, self.t0)["accounts"][0]
        self.assertEqual((account["account"], account["agents"], account["shares"]),
                         (CLAUDE, ["hand", "lead"], {"hand": 46.5, "lead": 15.5}))
        week = next(w for w in account["windows"] if w["main"])
        self.assertEqual((week["label"], week["used_percent"], week["left_percent"]), ("7 days", 62.0, 38.0))
        text = "\n".join(hub.costs_text(hub.costs_view(["lead", "hand"], self.t0 - 30 * DAY, self.t0), 30, "lead"))
        self.assertIn("the claude account of hand, lead: 7 days 62% used, 38% left, resets in 71 hours", text)
        self.assertIn("Points of its 7 days window: hand 46.5, lead 15.5, with its use outside the fleet spread over "
                      "them", text)

    def test_the_owner_reads_the_costs_of_every_agent_by_dates(self):
        self.usage("solo", [session("c1", self.t0 - 60, model="gpt-6.1-sol")], key=OPENAI)
        self.usage("hand", [session("h1", self.t0 - 60)])
        code, page = self.request("/ui/costs?db=test-generation")
        self.assertEqual(code, 200, page)
        self.assertEqual([a["agent"] for a in page["agents"]], ["manager", "lead", "hand", "solo"])
        self.assertEqual((page["unit"], page["minimum"]), ("list dollars", 3))
        solo = next(a for a in page["agents"] if a["agent"] == "solo")
        self.assertEqual({k: solo["now"][k] for k in ("sessions", "input", "cache_read", "cache_write", "output")},
                         dict(sessions=1, input=100, cache_read=900, cache_write=0, output=50))
        self.assertIn("costs", self.request()[1]["ui_features"])
        day = time.strftime("%Y-%m-%d", time.localtime(self.t0 - 40 * DAY))
        code, page = self.request(f"/ui/costs?db=test-generation&from={day}&to={day}&agent=hand&minimum=5")
        self.assertEqual((code, [a["agent"] for a in page["agents"]], page["minimum"]), (200, ["hand"], 5), page)
        self.assertEqual(page["agents"][0]["now"]["sessions"], 0)
        for query, status in (("db=old", 409), ("db=test-generation&from=yesterday-ish", 400),
                              ("db=test-generation&agent=nobody", 400), ("db=test-generation&minimum=0", 400),
                              ("db=test-generation&minimum=x", 400),
                              (f"db=test-generation&from={day}&to=2020-01-01", 400)):
            self.assertEqual(self.request(f"/ui/costs?{query}")[0], status, query)
        self.assertEqual(self.request("/ui/costs?db=test-generation", source="127.0.0.9")[0], 403)


class Scope(Base):
    """Every agent sees its own costs, a lead its team's, and the fleet manager every agent's."""

    def test_each_agent_reads_its_own_scope_and_only_the_costs_mode(self):
        for agent, rows in (("lead", [session("l1", self.t0 - 60)]), ("hand", [session("h1", self.t0 - 60)]),
                            ("solo", [session("c1", self.t0 - 60, model="gpt-6.1-sol")])):
            self.usage(agent, rows, key=OPENAI if agent == "solo" else CLAUDE)
        self.assertEqual(hub.costs_scope("hand"), ["hand"])
        self.assertEqual(hub.costs_scope("lead"), ["lead", "hand"])
        self.assertEqual(hub.costs_scope("manager"), ["manager", "lead", "hand", "solo"])
        hand = self.ok("hand", "see_history")
        self.assertIn("  hand (claude)", hand)
        self.assertNotIn("solo", hand)
        self.assertNotIn("set_agent_model", hand)           # a worker changes nobody's model
        lead = self.ok("lead", "see_history", what="costs")
        self.assertIn("  lead (claude)", lead)
        self.assertIn("  hand (claude)", lead)
        self.assertNotIn("solo (codex)", lead)
        self.assertIn("set_agent_model", lead)
        self.assertIn("  hand (claude)", self.ok("lead", "see_history", agent="hand"))
        manager = self.ok("manager", "see_history", what="costs")
        self.assertIn("  solo (codex)", manager)
        self.assertIn("  hand (claude)", manager)
        self.assertIn("refusals: ", self.ok("manager", "see_history", what="refusals", window=7) + "refusals: ")
        self.assertIn("is not one of them", self.refused("hand", "see_history", agent="solo"))
        self.assertIn("is not one of them", self.refused("lead", "see_history", agent="solo"))
        self.assertIn("must be one of costs", self.refused("hand", "see_history", what="agents"))
        self.assertIn("does not take duty", self.refused("hand", "see_history", duty="R-1"))
        # a task that a person's conversation opened, and a part of it, read nothing of it: the counts of reply tasks
        # by day tell a person how much the others used the agent (privacy between colleagues)
        opened = self.new_task("lead", title="Answer Ana", source_conversation=7)
        for agent, task in (("lead", opened), ("hand", self.new_task("hand", title="Find the order", parent=opened))):
            self.assertIn("reads no history of the fleet", self.refused(agent, "see_history", task=task, what="costs"))

    def test_a_worker_and_a_lead_have_the_short_costs_tool_and_the_manager_every_mode(self):
        def entry(agent):
            return next(t for t in hub.tools_for(agent) if t["name"] == "see_history")
        for agent in ("hand", "lead", "solo"):
            self.assertEqual(entry(agent)["inputSchema"]["properties"]["what"]["enum"], ["costs"], agent)
            self.assertTrue(entry(agent)["description"].startswith("What your work cost"), agent)
        self.assertIn("costs", entry("manager")["inputSchema"]["properties"]["what"]["enum"])
        self.assertIn("set_agent_model", [t["name"] for t in hub.tools_for("lead")])
        self.assertIn("set_agent_model", [t["name"] for t in hub.tools_for("manager")])
        self.assertNotIn("set_agent_model", [t["name"] for t in hub.tools_for("hand")])


class ModelChanges(Base):
    """set_agent_model: the one changer, inside the existing account, under the setting, each change recorded."""

    def setUp(self):
        super().setUp()
        for agent, runtime, models in (("hand", "claude", ("claude-sonnet-5-5", "claude-opus-5-5")),
                                       ("solo", "codex", ("gpt-6.1-sol", "gpt-6.1-sol-mini")),
                                       ("lead", "claude", ("claude-sonnet-5-5",))):
            helper_reports(agent, "session_kinds", models={
                "runtime": runtime, "ok": True, "read_at": time.time(), "other_names": False,
                "options": [{"model": m, "efforts": ["low", "medium", "high"], "default": i == 0}
                            for i, m in enumerate(models)]})

    def test_the_one_changer_sets_the_model_inside_the_account_and_each_change_is_recorded(self):
        said = self.ok("manager", "set_agent_model", agent="solo", model="gpt-6.1-sol-mini", effort="low",
                       why="routine checks need no large model")
        self.assertIn("solo runs gpt-6.1-sol-mini, low from its next session (it was its default model, its default "
                      "effort)", said)
        self.assertEqual({k: self.origin_team()["agents"]["solo"].get(k) for k in ("model", "effort")},
                         {"model": "gpt-6.1-sol-mini", "effort": "low"})
        self.assertEqual(hub.agents()["solo"]["model"], "gpt-6.1-sol-mini")             # applied at once
        change = hub.q1('SELECT agent, by, "from", "to", why FROM model_changes')
        self.assertEqual((change["agent"], change["by"], json.loads(change["from"]), json.loads(change["to"]),
                          change["why"]), ("solo", "manager", {"model": None, "effort": None},
                                           {"model": "gpt-6.1-sol-mini", "effort": "low"},
                                           "routine checks need no large model"))
        # the lead is its own worker's one changer, and "default" gives the runtime's own back
        self.ok("lead", "set_agent_model", agent="hand", model="claude-sonnet-5-5", effort="medium", why="drafts")
        self.ok("lead", "set_agent_model", agent="hand", model="default", effort="default", why="the drafts got worse")
        self.assertNotIn("model", self.origin_team()["agents"]["hand"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM model_changes WHERE agent='hand'")["n"], 2)
        self.assertIn("Nothing changed", self.ok("lead", "set_agent_model", agent="hand", model="default",
                                                 effort="default", why="again"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM model_changes")["n"], 3)
        # the costs say what changed, and when
        view = hub.costs_view(["hand", "solo"], self.t0 - DAY, self.t0 + 60)
        self.assertEqual([(m["agent"], m["by"]) for m in view["model_changes"]],
                         [("solo", "manager"), ("hand", "lead"), ("hand", "lead")])
        self.assertIn("manager set solo to gpt-6.1-sol-mini, low (it was its default model, its default effort): "
                      "routine checks need no large model", "\n".join(hub.costs_text(view, 1, "manager")))

    def test_only_the_one_changer_and_only_inside_the_account(self):
        self.assertIn("reports to lead", self.refused("manager", "set_agent_model", agent="hand", model="default",
                                                      effort="low", why="x"))
        self.assertIn("is the owner's to change", self.refused("lead", "set_agent_model", agent="manager",
                                                               model="default", effort="low", why="x"))
        self.assertIn("You have no tool named set_agent_model",
                      self.refused("hand", "set_agent_model", agent="hand", model="default", effort="low", why="x"))
        self.assertIn("not offered", self.refused("manager", "set_agent_model", agent="solo", model="gpt-9",
                                                  effort="low", why="a model of another account"))
        self.assertIn("not an effort", self.refused("manager", "set_agent_model", agent="solo", model="gpt-6.1-sol",
                                                    effort="max", why="x"))
        self.assertIn("why is one line", self.refused("manager", "set_agent_model", agent="solo", model="default",
                                                      effort="low", why=" "))
        helper_reports("solo", models=None)                                         # no current model list
        self.assertIn("no current model list", self.refused("manager", "set_agent_model", agent="solo",
                                                            model="gpt-6.1-sol", effort="low", why="x"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM model_changes")["n"], 0)
        self.assertNotIn("model", self.origin_team()["agents"]["solo"])
        # A lead whose Shell box is off changes no model (SHELL_OFF_TOOLS), so the fleet manager is its team's one
        # changer (task_giver; the KPI spec's finding of 20 November 2026), or nobody but the owner could be
        hub.TEAM["agents"]["lead"]["can"] = []
        self.ok("manager", "set_agent_model", agent="hand", model="claude-sonnet-5-5", effort="low",
                why="its lead changes no model")
        self.assertEqual(hub.q1("SELECT by FROM model_changes WHERE agent='hand'")["by"], "manager")

    def test_the_setting_turns_model_changes_off(self):
        hub.TEAM["settings"] = {"model_changes": False}
        self.assertIn("turned model changes off", self.refused("manager", "set_agent_model", agent="solo",
                                                               model="gpt-6.1-sol", effort="low", why="x"))
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM model_changes")["n"], 0)



class Slots(Base):
    """The lane "Tokens by day and model" (owner API 1.260): what each session spent, and when, in 15-minute slots,
    and GET /ui/costs by= over them."""

    def slots(self, agent):
        """{(session, slot, model): [its SLOT_FIELDS, machine]} of the agent's token slots."""
        return {(r["session_id"], r["slot"], r["model"]): [r[k] for k in hub.SLOT_FIELDS] + [r["machine"]]
                for r in hub.q("SELECT * FROM token_slots WHERE agent=?", (agent,))}

    def sums(self, agent, sid):
        """What the slots of one session add up to."""
        r = hub.q1("SELECT " + ", ".join(f"SUM({k}) {k}" for k in hub.SLOT_FIELDS) +
                   " FROM token_slots WHERE agent=? AND session_id=?", (agent, sid))
        return [r[k] for k in hub.SLOT_FIELDS]

    def totals(self, agent, sid):
        row = self.stored(agent, sid)
        return [row[k] for k in hub.SLOT_FIELDS]

    def test_a_report_adds_what_a_session_grew_by_in_the_slot_of_its_newest_call(self):
        """A helper sends each session's running totals every 30 seconds. Each report adds only what they grew by, in
        the slot of the session's newest call: a report that names it again with nothing new adds nothing, and the
        slots add up to the totals."""
        first, later = self.t0 - 3 * 3600, self.t0 - 600
        for _ in range(2):
            self.usage("hand", [session("s1", first, input=100, cache_read=900, cache_write=10, output=50, calls=4)])
        self.assertEqual(self.slots("hand"),
                         {("s1", hub.slot_of(first), "claude-opus-5-5"): [100, 900, 10, 50, 4, "hand-box"]})
        self.usage("hand", [session("s1", later, input=160, cache_read=1900, cache_write=10, output=80, calls=7)])
        self.assertEqual(self.slots("hand")[("s1", hub.slot_of(later), "claude-opus-5-5")], [60, 1000, 0, 30, 3,
                                                                                                "hand-box"])
        self.assertEqual(self.sums("hand", "s1"), self.totals("hand", "s1"))
        # the helper's machine has a clock of its own: a time ahead of the hub's puts nothing in a later slot
        self.usage("hand", [session("s2", self.t0 + 7200)])
        self.assertEqual([k[1] <= time.time() for k in self.slots("hand") if k[0] == "s2"], [True])
        # a stored row that is not counts (no code of the hub writes one) gives its session no slot and never stops the
        # report; the next start puts in what that session's slots lack
        hub.q("UPDATE session_tokens SET input='x' WHERE agent='hand' AND session_id='s1'")
        self.usage("hand", [session("s1", later, input=200, cache_read=1900, cache_write=10, output=80, calls=8),
                            session("s3", later, input=5, cache_read=0, output=1, calls=1)])
        self.assertEqual((self.sums("hand", "s3"), self.sums("hand", "s1")),
                         (self.totals("hand", "s3"), [160, 1900, 10, 80, 7]))
        self.assertEqual(hub.migrate(), [])
        self.assertEqual(self.sums("hand", "s1"), self.totals("hand", "s1"))
        # without a start, the session's next report puts in what its slots lack
        hub.q("UPDATE session_tokens SET input='x' WHERE agent='hand' AND session_id='s1'")
        self.usage("hand", [session("s1", later, input=230, cache_read=1900, cache_write=10, output=80, calls=9)])
        self.usage("hand", [session("s1", later, input=250, cache_read=1900, cache_write=10, output=90, calls=10)])
        self.assertEqual(self.sums("hand", "s1"), [250, 1900, 10, 90, 10])

    def test_each_model_gets_its_own_growth_also_after_a_report_without_the_split(self):
        """A workflow agent often runs another model than its session, so each model grows apart. A report without the
        split (one that it would take past the hub's size limit), or a split that moved, gives the session's growth
        at its own model; the next report with a split gives each model its own share again, and no token is lost or
        counted twice."""
        at, slot = self.t0 - 600, hub.slot_of(self.t0 - 600)

        def mixed(opus, haiku):
            totals = dict(zip(hub.SLOT_FIELDS, (a + b for a, b in zip(opus, haiku))))
            return dict(session("m1", at, **totals), models=[["claude-opus-5-5", *opus], ["claude-haiku-5-5", *haiku]])

        def held():
            got = self.slots("hand")
            return got[("m1", slot, "claude-opus-5-5")][:5], got[("m1", slot, "claude-haiku-5-5")][:5]
        self.usage("hand", [mixed([100, 0, 0, 10, 1], [50, 0, 0, 5, 2])])
        self.usage("hand", [mixed([300, 0, 0, 30, 2], [60, 0, 0, 6, 3])])
        self.assertEqual(held(), ([300, 0, 0, 30, 2], [60, 0, 0, 6, 3]))
        self.usage("hand", [session("m1", at, **dict(zip(hub.SLOT_FIELDS, [500, 0, 0, 50, 6])))])
        self.assertEqual(held(), ([440, 0, 0, 44, 3], [60, 0, 0, 6, 3]))
        # the stored split is stale now: what each model's slots hold gives each model its own share again
        self.usage("hand", [mixed([600, 0, 0, 60, 4], [90, 0, 0, 9, 4])])
        self.assertEqual(held(), ([600, 0, 0, 60, 4], [90, 0, 0, 9, 4]))
        # a split that moved (haiku's part folded into another): the growth goes to the session's model
        self.usage("hand", [mixed([650, 0, 0, 65, 5], [80, 0, 0, 8, 4])])
        self.assertEqual(held(), ([640, 0, 0, 64, 5], [90, 0, 0, 9, 4]))
        self.assertEqual(self.sums("hand", "m1"), self.totals("hand", "m1"))

    def test_a_reading_that_goes_down_takes_nothing_away(self):
        """A record that the helper reads no more makes a session's totals smaller: what was spent stays in the slots,
        and what the session spends after it adds to them."""
        at = self.t0 - 600
        self.usage("hand", [session("d1", at, input=1000, cache_read=0, output=100, calls=5)])
        self.usage("hand", [session("d1", at, input=400, cache_read=0, output=40, calls=2)])
        self.assertEqual(self.sums("hand", "d1"), [1000, 0, 0, 100, 5])
        self.usage("hand", [session("d1", at, input=500, cache_read=0, output=50, calls=3)])
        self.assertEqual(self.sums("hand", "d1"), [1100, 0, 0, 110, 6])
        # what it grows by past what the slots hold is new spending too, not only the part above them
        self.usage("hand", [session("d1", at, input=1300, cache_read=0, output=130, calls=7)])
        self.assertEqual(self.sums("hand", "d1"), [1900, 0, 0, 190, 10])

    def test_each_start_puts_in_what_the_slots_lack_and_nothing_twice(self):
        """The sessions from before the slots, and what a release without them recorded (a rollback), go into the slot
        of each session's last activity at the next start of the hub, and never into one after its last report; a
        start after it adds nothing, and a session that such a release gave to another agent takes its slots along."""
        old_at, new_at = self.t0 - 5 * DAY, self.t0 - DAY
        split = [["claude-opus-5-5", 60, 900, 0, 60, 1], ["claude-haiku-5-5", 40, 0, 0, 40, 3]]
        cols = "agent,session_id,total,last_activity,reported,input,cache_read,cache_write,output,calls,model"
        hub.q(f"INSERT INTO session_tokens({cols},models,runtime) VALUES('hand','old',1100,?,?,100,900,0,100,4,"
              "'claude-opus-5-5',?,'claude')", (old_at, old_at, json.dumps(split)))
        hub.q("INSERT INTO session_tokens(agent,session_id,total,last_activity,reported) VALUES('hand','plain',50,?,?)",
              (old_at, old_at))                     # a session from before the four kinds has nothing to split
        hub.q(f"INSERT INTO session_tokens({cols}) VALUES('hand','ahead',10,?,?,10,0,0,0,1,'claude-opus-5-5')",
              (self.t0 + 5 * 3600, self.t0 - 60))   # its helper's clock was ahead of the hub's
        for sid, kinds, last in (("odd", "'x',0,0,0,1", old_at), ("odd-time", "10,0,0,0,1", "x"),
                                 ("odd-past", "10,0,0,0,1", -1e19)):
            hub.q(f"INSERT INTO session_tokens({cols}) VALUES('hand',?,10,?,?,{kinds},'claude-opus-5-5')",
                  (sid, last, old_at))      # no code of the hub writes these: they get no slot, and stop nothing
        self.assertEqual(hub.migrate(), [])
        got = self.slots("hand")
        self.assertEqual({k: v for k, v in got.items() if k[0] == "old"},
                         {("old", hub.slot_of(old_at), "claude-opus-5-5"): [60, 900, 0, 60, 1, None],
                          ("old", hub.slot_of(old_at), "claude-haiku-5-5"): [40, 0, 0, 40, 3, None]})
        self.assertEqual(sorted((k[0], k[1]) for k in got if k[0] != "old"), [("ahead", hub.slot_of(self.t0 - 60))])
        since = hub.kv_get(hub.TOKEN_SLOTS_FROM)
        self.assertIsNotNone(since)
        self.assertEqual(hub.migrate(), [])
        self.assertEqual(self.sums("hand", "old"), [100, 900, 0, 100, 4])
        # a release without the slots recorded more of the session: the next start puts in what they lack
        hub.q("UPDATE session_tokens SET input=130, output=110, calls=5, total=1140, last_activity=?, reported=?, "
              "models=NULL WHERE session_id='old'", (new_at, new_at))
        self.assertEqual(hub.migrate(), [])
        self.assertEqual(self.slots("hand")[("old", hub.slot_of(new_at), "claude-opus-5-5")], [30, 0, 0, 10, 1, None])
        # and it renamed the agent, or deleted it: the session's slots go with the session, and nothing counts twice
        hub.q("UPDATE session_tokens SET agent='lead' WHERE session_id='old'")
        self.assertEqual(hub.migrate(), [])
        self.assertEqual(([k for k in self.slots("hand") if k[0] == "old"], self.sums("lead", "old")),
                         ([], [130, 900, 0, 110, 5]))
        self.assertEqual(hub.kv_get(hub.TOKEN_SLOTS_FROM), since)

    def test_the_owner_reads_the_tokens_by_day_agent_model_kind_and_machine(self):
        """GET /ui/costs by=: the tokens of the period by the parts that it names, a day in the fleet's own time zone
        (00:20 in Madrid is the day before in UTC), each model at its own list prices, a deleted agent under its name
        with the time of its delete, and each slot in the period of its start."""
        import datetime
        import zoneinfo
        hub.TEAM["goals"] = {"timezone": "Europe/Madrid"}
        zone = zoneinfo.ZoneInfo("Europe/Madrid")
        day = (datetime.datetime.now(zone) - datetime.timedelta(days=1)).date()
        midnight = datetime.datetime.combine(day, datetime.time(0, 0), zone).timestamp()
        next_midnight = datetime.datetime.combine(day + datetime.timedelta(days=1), datetime.time(0, 0),
                                                  zone).timestamp()
        early, noon = midnight + 20 * 60, midnight + 12 * 3600
        self.link(self.new_task("hand"), "h1")
        self.usage("hand", [session("h1", early, input=1_000_000, cache_read=0, output=0, calls=2),
                            dict(session("h2", noon, input=500_000, cache_read=0, output=0, calls=3),
                                 models=[["claude-opus-5-5", 300_000, 0, 0, 0, 1],
                                         ["claude-haiku-5-5", 200_000, 0, 0, 0, 2]])])
        self.usage("solo", [session("c1", noon, input=100_000, cache_read=0, output=0, calls=1, model="gpt-6.1-sol")],
                   key=OPENAI)

        def read(query):
            code, page = self.request(f"/ui/costs?db=test-generation&{query}")
            self.assertEqual(code, 200, page)
            return page, [{k: v for k, v in r.items() if k not in ("cache_read", "cache_write", "output")}
                          for r in page["rows"]]
        book = hub.price_book()
        price = {m: hub.token_price(book[r], m)["input"] for m, r in (("claude-opus-5-5", "claude"),
                                                                       ("claude-haiku-5-5", "claude"),
                                                                       ("gpt-6.1-sol", "codex"))}
        page, rows = read(f"by=day,agent&from={day}&to={day}")
        self.assertEqual([{k: v for k, v in r.items() if k != "cost"} for r in rows],
                         [dict(day=day.isoformat(), agent="hand", input=1_500_000, calls=5),
                          dict(day=day.isoformat(), agent="solo", input=100_000, calls=1)])
        # a group of several models: each model at its own price
        self.assertAlmostEqual(rows[0]["cost"], price["claude-opus-5-5"] * 1.3 + price["claude-haiku-5-5"] * 0.2,
                               places=4)
        self.assertAlmostEqual(rows[1]["cost"], price["gpt-6.1-sol"] * 0.1, places=4)
        self.assertEqual((page["zone"], page["unit"], page["by"], page["total"]["input"]),
                         ("Europe/Madrid", "list dollars", ["day", "agent"], 1_600_000))
        self.assertIsNotNone(page["exact_from"])
        _, rows = read("by=model")
        self.assertEqual([(r["model"], r["input"]) for r in rows],
                         [("claude-haiku-5-5", 200_000), ("claude-opus-5-5", 1_300_000), ("gpt-6.1-sol", 100_000)])
        for r in rows:
            self.assertAlmostEqual(r["cost"], price[r["model"]] * r["input"] / 1e6, places=4)
        self.assertEqual([(r["kind"], r["input"]) for r in read("by=kind")[1]],
                         [("standing", 600_000), ("task", 1_000_000)])
        self.assertEqual([(r["machine"], r["input"]) for r in read("by=machine")[1]],
                         [("hand-box", 1_500_000), ("solo-box", 100_000)])
        self.assertEqual([r["agent"] for r in read("by=agent&agent=solo")[1]], ["solo"])
        self.assertIn("costs_by", self.request()[1]["ui_features"])
        for query in ("by=week", "by=day,day", "by=day;agent"):
            self.assertEqual(self.request(f"/ui/costs?db=test-generation&{query}")[0], 400, query)
        # an agent that the owner deleted, whose name went free: its slots stay, under its name and its delete's time
        gone = hub.spent_name("gone", 1_700_000_000.0)
        hub.q("INSERT INTO session_tokens(agent,session_id,total,last_activity,reported,input,cache_read,cache_write,"
              "output,calls,model,runtime,kind) VALUES(?,'g1',10,?,?,10,0,0,0,1,'claude-opus-5-5','claude','task')",
              (gone, noon, noon))
        hub.q("INSERT INTO token_slots(agent,session_id,slot,model,input,cache_read,cache_write,output,calls) "
              "VALUES(?,'g1',?,'claude-opus-5-5',10,0,0,0,1)", (gone, hub.slot_of(noon)))
        self.assertEqual([(r["agent"], r.get("deleted"), r["input"]) for r in read("by=agent")[1]],
                         [("gone", 1_700_000_000.0, 10), ("hand", None, 1_500_000), ("solo", None, 100_000)])
        # the period: a slot counts in the period of its start, and a date's period ends at the next midnight
        self.usage("hand", [session("h0", midnight - 2 * DAY + 12 * 3600, input=7_000, cache_read=0, output=0),
                            session("h9", next_midnight + 300, input=3_000, cache_read=0, output=0)])
        self.assertEqual([(r["day"], r["input"]) for r in read(f"by=day&from={day}&to={day}")[1]],
                         [(day.isoformat(), 1_600_010)])
        by_day = {r["day"]: r["input"] for r in read("by=day")[1]}
        self.assertEqual(by_day[(day - datetime.timedelta(days=2)).isoformat()], 7_000)

    def test_every_provider_counts_at_its_own_prices_and_a_model_of_the_owner_s_own_costs_nothing(self):
        """The owner, 20 November 2026: "make sure it works with any ai model provider!!". An ACP runtime's models
        are priced from the price file, each at its own; a Codex agent that runs a model on its own machine (--oss)
        names it own/<model> and it costs nothing, also in the slots that a start fills; each thread of an agent's
        screen tasks is a session of its own, at its model's price and on the screen's account."""
        at = self.t0 - 600
        book = hub.price_book()

        def costs(query="by=model"):
            code, page = self.request(f"/ui/costs?db=test-generation&{query}")
            self.assertEqual(code, 200, page)
            return {r["model"]: r for r in page["rows"]}
        acp = next(n for n, e in lifecycle.RUNTIMES.items() if e["driver"] == "acp")
        hub.record_session_tokens("scout", [dict(session("a1", at, input=3_000_000, cache_read=0, output=0, calls=3,
                                                         model="grok-4.3"),
                                                 models=[["grok-4.3", 2_000_000, 0, 0, 0, 2],
                                                         ["qwen3.8-max", 1_000_000, 0, 0, 0, 1]])], acp, None)
        got = costs()
        for model, tokens in (("grok-4.3", 2_000_000), ("qwen3.8-max", 1_000_000)):
            self.assertAlmostEqual(got[model]["cost"], hub.token_price(book[acp], model)["input"] * tokens / 1e6,
                                   places=4, msg=model)
        self.assertNotEqual(hub.token_price(book[acp], "grok-4.3"), hub.token_price(book[acp], "qwen3.8-max"))
        # a Codex agent on a model of its own machine: own/<model>, at no cost
        hub.TEAM["agents"]["solo"]["start"] = "codex --oss"
        self.usage("solo", [session("o1", at, input=500_000, cache_read=0, output=0, model="gpt-oss:20b")], key=OPENAI)
        self.assertEqual((costs()["own/gpt-oss:20b"]["input"], costs()["own/gpt-oss:20b"]["cost"]), (500_000, 0.0))
        self.assertNotIn("gpt-oss:20b", costs())
        # and in every reader of the sessions: the session's own row names it own/ too, so its costs are nothing
        self.assertEqual(self.stored("solo", "o1")["model"], "own/gpt-oss:20b")
        self.assertEqual(hub.costs_view(["solo"], self.t0 - 30 * DAY, self.t0 + 60)["agents"][0]["now"]["cost"], 0.0)
        # a session of it from before the slots: the next start fills its slots under the same own/ name
        hub.q("INSERT INTO session_tokens(agent,session_id,total,last_activity,reported,input,cache_read,cache_write,"
              "output,calls,model,runtime) VALUES('solo','o0',70,?,?,70,0,0,0,1,'gpt-oss:20b','codex')", (at, at))
        self.assertEqual(hub.migrate(), [])
        self.assertEqual([k[2] for k in self.slots("solo") if k[0] == "o0"], ["own/gpt-oss:20b"])
        # the screen tasks of an agent: each thread a session of the screen runtime (usage.screen_tokens), at its own
        # last activity, and on the screen's account, not on the agent's own model account
        hub.TEAM["accounts"] = {"team-key": {"kind": "key", "provider": "anthropic"}}
        hub.TEAM["agents"]["hand"]["account"] = "team-key"
        older = at - 2 * DAY

        def screen(threads):
            rows = [dict(session_id=thread, total=n, last_activity=last, input=n, cache_read=0, cache_write=0, output=0,
                         calls=0, model=model, first_cache_share=None) for thread, n, last, model in threads]
            tokens = dict(input=sum(n for _, n, *_ in threads), output=0, cache_read=0, cache_write=0,
                          total=sum(n for _, n, *_ in threads), sessions=len(threads), since=older - 60,
                          last_activity=max(last for _, _, last, _ in threads), collected_at=time.time(),
                          source=usage.SCREEN_SOURCE, scope=usage.SCREEN_SCOPE, error=None, by_session=rows)
            return dict(tokens=tokens, limits=report([], runtime=usage.SCREEN_RUNTIME, key=OPENAI)["limits"])
        for threads in ([("t-1", 200_000, older, None)],
                        [("t-1", 200_000, older, None), ("t-2", 60_000, at, "gpt-6.1-sol")]):
            data = report([session("h1", at)])
            data["screen"] = screen(threads)
            self.assertEqual(self.request("/helper/usage/hand", data, source=SOURCE["hand"])[0], 200)
        first, second = self.stored("hand", "t-1"), self.stored("hand", "t-2")
        self.assertEqual((first["runtime"], first["account"], second["account"], second["input"]),
                         (usage.SCREEN_RUNTIME, OPENAI, OPENAI, 60_000))
        self.assertEqual(self.stored("hand", "h1")["account"], "account:team-key")
        self.assertEqual([k[1] for k in self.slots("hand") if k[0] == "t-1"], [hub.slot_of(older)])
        # a thread with the model that its start named: under that model, at its price on the screen runtime
        self.assertEqual((second["model"], [k[2] for k in self.slots("hand") if k[0] == "t-2"]),
                         ("gpt-6.1-sol", ["gpt-6.1-sol"]))
        for model, tokens in ((None, 200_000), ("gpt-6.1-sol", 60_000)):
            self.assertAlmostEqual(costs()[model]["cost"],
                                   hub.token_price(book[usage.SCREEN_RUNTIME], model)["input"] * tokens / 1e6, places=4)
        # a hub that takes no four kinds gets the screen's threads with their totals alone, as every other session
        self.assertEqual(set(usage.plain_sessions(data)["screen"]["tokens"]["by_session"][0]), set(usage.SESSION_FIELDS))


if __name__ == "__main__":
    unittest.main()

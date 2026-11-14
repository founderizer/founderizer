"""The hub's own faults and refused calls (diagnostics.py, the lane "Bug reports"): what is kept is a class from a
fixed list, files and lines of the code tree, numbers and times, and never the words of a fault.

The owner, 14 November 2026: "Pictures first (Recommended)" and, to the pictures C0, E1, E2 and E3, "ok yes, make
sure we include all relevant inforamtion that is SAFE to send". So most of these tests are about what must NOT reach
GET /ui/diagnostics: a message, a secret, a path of the machine, a name of the fleet's work.

The first class needs no hub. The second runs the test hub of test_ui_api (OwnerAPI), as test_health does: a
temporary database, its own checkout, and nothing of the developer's own fleet."""
import contextlib
import http.client
import inspect
import io
import json
import os
import re
import types
import unittest
import unittest.mock
import urllib.error
import uuid

import diagnostics
import hub
from test_ui_api import OwnerAPI

HERE = os.path.basename(__file__)


def canary():
    """Words that look like a key and a person's work, different in each test."""
    return f"sk-ant-api03-CANARY{uuid.uuid4().hex} for Ana's task about /Users/ana/secret-plans"


def strings(value):
    """Every text in a decoded answer, keys left out."""
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return [value] if isinstance(value, str) else []


def leaves(value):
    if isinstance(value, dict):
        return [x for v in value.values() for x in leaves(v)]
    if isinstance(value, list):
        return [x for v in value for x in leaves(v)]
    return [value]


class CanaryLeak(Exception):
    """A class that is not on the list: its name is the code's choice, so it goes as "other"."""


def fail_with(exc):
    def deeper():
        raise exc
    deeper()


class Recorder(unittest.TestCase):
    def setUp(self):
        diagnostics.pending()       # what an earlier test counted is not this test's

    def recorded(self, exc, program="hub"):
        try:
            fail_with(exc)
        except Exception:
            diagnostics.record(program)
        return diagnostics.pending()

    def test_a_fault_keeps_its_class_and_places_and_never_its_words(self):
        words = canary()
        taken = self.recorded(KeyError(words))
        self.assertEqual(len(taken), 1)
        fault = taken[0]
        self.assertEqual((fault["kind"], fault["program"], fault["name"]), ("fault", "hub", "KeyError"))
        self.assertEqual(fault["frames"][-1][0], HERE)                  # the innermost frame: where it was raised
        self.assertIsInstance(fault["frames"][-1][1], int)
        text = json.dumps(taken)
        self.assertNotIn("CANARY", text)
        self.assertNotIn("Ana", text)
        self.assertNotIn(os.path.dirname(os.path.abspath(__file__)), text)    # no path of this machine

    def test_a_class_that_is_not_on_the_list_goes_as_other(self):
        self.assertEqual(self.recorded(CanaryLeak(canary()))[0]["name"], "other")

    def test_a_frame_outside_the_code_tree_is_lib_with_no_line(self):
        try:
            json.loads("{" + canary())
        except ValueError:
            diagnostics.record("hub")
        frames = diagnostics.pending()[0]["frames"]
        self.assertIn(["lib", 0], frames)
        self.assertEqual({f[0] for f in frames} - {"lib", HERE}, set())

    def test_errno_and_http_status_are_numbers_and_the_message_stays_behind(self):
        fault = self.recorded(PermissionError(13, canary()))[0]
        self.assertEqual((fault["name"], fault["errno"], fault["http"]), ("PermissionError", 13, None))
        words = canary()
        fault = self.recorded(urllib.error.HTTPError("https://example.com/" + words, 503, words, None, None))[0]
        self.assertEqual((fault["name"], fault["http"]), ("HTTPError", 503))
        self.assertNotIn("CANARY", json.dumps(fault))

    def test_the_recorder_never_raises(self):
        diagnostics.record("hub")                                   # no exception is being handled
        diagnostics.record("hub", info=(None, object(), "not a traceback"))
        diagnostics.refused("send_message", info=(None, object(), 42))
        with unittest.mock.patch.object(diagnostics, "places", side_effect=RecursionError("deep")):
            self.recorded(KeyError("x"))
        self.assertEqual(self.recorded(KeyError("x"), program="someone-else"), [])     # a program not on the list
        self.assertEqual(diagnostics.pending(), [])

    def test_one_kind_counts_its_times_and_keeps_its_first_and_last(self):
        clock = iter([100.0, 200.0, 300.0])
        for _ in range(3):
            try:
                raise KeyError("same place")
            except KeyError:
                diagnostics.record("hub", clock=lambda: next(clock))
        (fault,) = diagnostics.pending()
        self.assertEqual((fault["count"], fault["first"], fault["last"]), (3, 100.0, 300.0))

    def test_the_kinds_that_wait_in_memory_are_bounded(self):
        for n in range(diagnostics.MAX_KINDS + 50):
            diagnostics._count(("fault", "hub", "KeyError", (("hub.py", n + 1),)), 1.0)
        self.assertEqual(len(diagnostics.pending()), diagnostics.MAX_KINDS)

    def test_a_refused_call_keeps_its_tool_and_its_place(self):
        for tool, kept in (("send_message", "send_message"), ("Bad Name " + canary(), "other"), (None, "other")):
            try:
                fail_with(hub.ToolError(canary()))
            except hub.ToolError:
                diagnostics.refused(tool)
            (row,) = diagnostics.pending()
            self.assertEqual((row["kind"], row["name"]), ("refusal", kept))
            self.assertEqual(len(row["frames"]), 1)
            self.assertEqual(row["frames"][0][0], HERE)
            self.assertNotIn("CANARY", json.dumps(row))

    def test_refused_calls_never_crowd_out_a_fault(self):
        for n in range(diagnostics.MAX_KINDS + 50):
            diagnostics._count(("refusal", "hub", "send_message", (("hub.py", n + 1),)), 1.0)
        try:
            fail_with(KeyError("y"))
        except KeyError:
            diagnostics.record("hub")
        kinds = [row["kind"] for row in diagnostics.pending()]
        self.assertEqual(kinds.count("refusal"), diagnostics.MAX_KINDS)
        self.assertEqual(kinds.count("fault"), 1)

    def test_the_code_id_is_the_same_at_every_reading_of_the_same_tree(self):
        diagnostics._code.clear()
        first = diagnostics.code_id()
        diagnostics._code.clear()
        import thread_door  # noqa: F401  (a module that the hub imports late: it must not change the id)
        self.assertEqual(diagnostics.code_id(), first)
        self.assertRegex(first, r"^[0-9a-f]{24}$")

    def test_the_answer_keeps_only_tools_of_the_hubs_list_and_files_of_the_tree(self):
        refusal = {"kind": "refusal", "program": "hub", "name": "nova_acme_merger", "frames": '[["hub.py",9]]',
                   "errno": None, "http": None, "count": 1, "first": 5.0, "last": 6.0}
        self.assertEqual(diagnostics.view([refusal], tools={"send_message"})["refusals"], [])
        self.assertEqual(len(diagnostics.view([dict(refusal, name="send_message")], tools={"send_message"})["refusals"]), 1)
        self.assertEqual(len(diagnostics.view([dict(refusal, name="other")], tools={"send_message"})["refusals"]), 1)
        fault = {"kind": "fault", "program": "hub", "name": "KeyError", "frames": '[["Acme_layoffs_list.py",3]]',
                 "errno": None, "http": None, "count": 1, "first": 5.0, "last": 6.0}
        self.assertEqual(diagnostics.view([fault])["faults"], [])

    def test_frames_nested_too_deep_drop_their_row_and_raise_nothing(self):
        row = {"kind": "fault", "program": "hub", "name": "KeyError", "frames": "[" * 100_000 + "]" * 100_000,
               "errno": None, "http": None, "count": 1, "first": 5.0, "last": 6.0}
        self.assertEqual(diagnostics.view([row]), {"faults": [], "refusals": []})


    def test_a_deep_recursion_keeps_its_innermost_twelve_frames(self):
        def down(n):
            if n == 0:
                raise RecursionError("deep " + canary())
            down(n - 1)
        try:
            down(40)
        except RecursionError:
            diagnostics.record("hub")
        (fault,) = diagnostics.pending()
        self.assertEqual(len(fault["frames"]), diagnostics.MAX_FRAMES)
        self.assertEqual(len(diagnostics.view([dict(fault, frames=json.dumps(fault["frames"]))])["faults"]), 1)

    def test_the_answer_checks_numbers_and_shows_at_most_twenty_of_each(self):
        row = {"kind": "fault", "program": "hub", "name": "KeyError", "frames": '[["hub.py",120]]',
               "errno": 10 ** 9, "http": 999, "count": 1, "first": 1.0, "last": 2.0}
        (fault,) = diagnostics.view([row])["faults"]
        self.assertEqual((fault["errno"], fault["http"]), (None, None))
        many = [dict(row, frames=f'[["hub.py",{n}]]', last=float(n)) for n in range(1, 31)]
        self.assertEqual(len(diagnostics.view(many)["faults"]), diagnostics.MAX_SHOWN)

    def test_the_answer_checks_every_value_again_and_keeps_no_free_text(self):
        good = {"kind": "fault", "program": "hub", "name": "KeyError", "frames": '[["hub.py",120],["lib",0]]',
                "errno": None, "http": None, "count": 2, "first": 10.0, "last": 20.0}
        refusal = {"kind": "refusal", "program": "hub", "name": "send_message", "frames": '[["hub.py",9]]',
                   "errno": None, "http": None, "count": 1, "first": 5.0, "last": 6.0}
        bad = [dict(good, name="Secret " + canary()), dict(good, frames='[["/home/ana/x.py",3]]'),
               dict(good, frames='[["../x.py",3]]'), dict(good, frames='[["lib",7]]'), dict(good, count=-1),
               dict(good, frames="not json"), dict(good, program="ana"), dict(refusal, name="Ana's " + canary()),
               dict(good, frames=json.dumps([["hub.py", 1]] * (diagnostics.MAX_FRAMES + 1)))]
        answer = diagnostics.view([good, refusal] + bad)
        self.assertEqual(len(answer["faults"]), 1)
        self.assertEqual(len(answer["refusals"]), 1)
        self.assertEqual(answer["faults"][0]["frames"], [{"file": "hub.py", "line": 120}, {"file": "lib", "line": 0}])
        # No free text anywhere: each text is a class of the list, a program, a file of the tree or "lib", or a tool.
        for text in strings(answer):
            self.assertTrue(text in diagnostics.CLASSES or text in ("other", "lib") or text in diagnostics.PROGRAMS
                            or diagnostics.FILE.fullmatch(text) or diagnostics.NAME.fullmatch(text), text)
        for leaf in leaves(answer):
            self.assertTrue(leaf is None or isinstance(leaf, (str, int, float)), leaf)
        self.assertNotIn("CANARY", json.dumps(answer))


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(Recorder))
    suite.addTests(OnTheHub(name) for name in OnTheHub.__dict__ if name.startswith("test_"))
    return suite


class OnTheHub(OwnerAPI):
    def setUp(self):
        super().setUp()
        diagnostics.pending()
        # As test_health: a checkout of the hub's own, and an empty `~/.fleet` of this test.
        kit = os.path.join(self.tmp.name, "kit")
        os.makedirs(os.path.join(kit, "profiles"))
        with open(os.path.join(kit, "team.json"), "w") as f:
            json.dump(hub.TEAM, f)
        hub.CFG["team_path"] = os.path.join(kit, "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        for key, name in (("google_file", "google.json"), ("mcp_file", "mcp.json"),
                          ("github_app", "github-app.pem"), ("attachment_dir", "attachments")):
            hub.CFG[key] = os.path.join(self.tmp.name, "fleet-home", name)
            self.addCleanup(hub.CFG.pop, key, None)

    def fault(self, times=1):
        words = canary()
        for _ in range(times):
            try:
                fail_with(KeyError(words))
            except KeyError:
                with contextlib.redirect_stderr(io.StringIO()):     # the journal's copy, as before
                    hub.print_fault()           # as each of the hub's 18 handlers does
        with hub.LOCK:
            hub.fault_flush(hub.now())
        return words

    def test_a_handled_fault_reaches_the_route_with_no_words(self):
        self.assertIn("diagnostics", hub.UI_FEATURES)
        words = self.fault(times=2)
        code, answer = self.request("/ui/diagnostics?db=test-generation")
        self.assertEqual(code, 200)
        (fault,) = answer["faults"]
        self.assertEqual((fault["class"], fault["count"], fault["program"]), ("KeyError", 2, "hub"))
        self.assertEqual(fault["frames"][-1]["file"], HERE)
        self.assertNotIn(words.split(" ")[0], json.dumps(answer))
        self.assertNotIn("Ana", json.dumps(answer))
        self.assertEqual(self.request("/ui/diagnostics?db=another")[0], 409)

    def test_the_route_is_the_owners_only(self):
        self.fault()
        code, _ = self.request("/ui/diagnostics?db=test-generation", source="127.0.0.9")
        self.assertNotEqual(code, 200)

    def test_a_refused_tool_call_is_counted_with_its_tool_or_other(self):
        said, refused = hub.call_tool("manager", "no_such_tool_" + uuid.uuid4().hex[:6], {})
        self.assertTrue(refused)
        with hub.LOCK:
            hub.fault_flush(hub.now())
        (row,) = self.request("/ui/diagnostics?db=test-generation")[1]["refusals"]
        self.assertEqual(row["tool"], "other")
        self.assertEqual(row["file"], "hub.py")
        self.assertNotIn("no_such_tool", json.dumps(row))

    def test_system_status_says_how_many_times_and_since_when(self):
        self.fault(times=3)
        with hub.LOCK:
            warnings = [w for w in hub.health_view()["warnings"] if w["kind"] == "hub_fault"]
        self.assertEqual(len(warnings), 1)
        self.assertRegex(warnings[0]["detail"], r"^3 times since .+\.$")
        self.assertIsNone(warnings[0]["fix"])

    def test_one_fault_says_once(self):
        self.fault()
        with hub.LOCK:
            (warning,) = [w for w in hub.health_view()["warnings"] if w["kind"] == "hub_fault"]
        self.assertRegex(warning["detail"], r"^Once at .+\.$")

    def test_no_fault_no_warning(self):
        with hub.LOCK:
            self.assertEqual([w for w in hub.health_view()["warnings"] if w["kind"] == "hub_fault"], [])

    def test_rows_of_other_code_and_old_rows_end_at_the_next_write(self):
        hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                ("old-code", "fault", "hub", "KeyError", '[["hub.py",1]]', 1, 1.0, hub.now(), "another-code"))
        hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                ("too-old", "fault", "hub", "KeyError", '[["hub.py",2]]', 1, 1.0,
                 hub.now() - (hub.FAULT_DAYS + 1) * 86400, diagnostics.code_id()))
        self.fault()
        kept = {r["sig"] for r in hub.q("SELECT sig FROM faults")}
        self.assertNotIn("old-code", kept)
        self.assertNotIn("too-old", kept)
        self.assertEqual(len(kept), 1)

    def test_writing_the_counts_wakes_no_app(self):
        before = hub.CHANGE["state"]
        self.fault()
        self.assertEqual(hub.CHANGE["state"], before)

    def test_a_row_older_than_its_days_is_not_answered_before_a_write_ends_it(self):
        hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                ("too-old", "fault", "hub", "KeyError", '[["hub.py",2]]', 1, 1.0,
                 hub.now() - (hub.FAULT_DAYS + 1) * 86400, diagnostics.code_id()))
        self.assertEqual(self.request("/ui/diagnostics?db=test-generation")[1]["faults"], [])

    def test_a_database_without_the_table_answers_nothing_and_keeps_its_health(self):
        hub.ins("DROP TABLE faults")
        code, answer = self.request("/ui/diagnostics?db=test-generation")
        self.assertEqual((code, answer["faults"], answer["refusals"]), (200, [], []))
        with hub.LOCK:
            self.assertEqual([w for w in hub.health_view()["warnings"] if w["kind"] == "hub_fault"], [])

    def test_a_length_that_is_not_a_number_is_the_callers_mistake_and_no_fault(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        connection.putrequest("POST", "/ui/command")
        connection.putheader("Content-Length", "z")
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 400)
        connection.close()
        self.assertEqual([row for row in diagnostics.pending() if row["kind"] == "fault"], [])

    def test_rpc_params_that_are_not_an_object_are_the_callers_mistake_and_no_fault(self):
        for params in ([1], "x", 3):        # an empty list is "no params", which the call takes
            answer = hub.rpc("manager", {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params}, {})
            self.assertEqual(answer["error"]["code"], -32602)
        answer = hub.rpc("manager", {"jsonrpc": "2.0", "id": 2, "method": "initialize",
                                     "params": {"clientInfo": ["a list"]}}, {})
        self.assertNotIn("error", answer)
        self.assertEqual(diagnostics.pending(), [])


    def test_every_handler_counts_its_fault(self):
        with open(hub.__file__, encoding="utf-8") as f:
            source = f.read()
        self.assertEqual(source.count("traceback.print_exc()"), 1)      # only print_fault's own
        self.assertIn("step(fault_flush, t0)", source)
        start = inspect.getsource(hub.main)                           # read at the start, and a dying thread
        self.assertIn("diagnostics.code_id()", start)
        self.assertIn("threading.excepthook = thread_fault", start)

    def test_the_tick_writes_what_was_counted(self):
        try:
            fail_with(KeyError(canary()))
        except KeyError:
            with contextlib.redirect_stderr(io.StringIO()):
                hub.print_fault()
        hub.tick()
        self.assertEqual([r["name"] for r in hub.q("SELECT name FROM faults")], ["KeyError"])

    def test_counts_add_up_across_writes(self):
        def burst(times, at):
            for _ in range(times):
                try:
                    fail_with(KeyError("the same place"))
                except KeyError:
                    diagnostics.record("hub", clock=lambda: at)
            with hub.LOCK:
                hub.fault_flush(hub.now())
        first = round(hub.now() - 120, 3)
        burst(2, first)
        burst(1, first + 60)
        (fault,) = self.request("/ui/diagnostics?db=test-generation")[1]["faults"]
        self.assertEqual((fault["count"], fault["first"], fault["last"]), (3, first, round(first + 60, 3)))

    def test_the_routes_gate_answers_nothing_when_a_registered_login_is_in_it(self):
        self.fault()
        with unittest.mock.patch.object(hub, "secret_hit", return_value=True):
            code, answer = self.request("/ui/diagnostics?db=test-generation")
        self.assertEqual((code, answer["faults"], answer["refusals"]), (200, [], []))

    def test_the_warning_counts_only_recent_faults_of_this_code(self):
        def row(sig, kind, last, code):
            hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                    (sig, kind, "hub", "KeyError" if kind == "fault" else "read_messages", '[["hub.py",2]]', 5,
                     last, last, code))
        row("old", "fault", hub.now() - (hub.FAULT_WARN_HOURS + 1) * 3600, diagnostics.code_id())
        row("refused", "refusal", hub.now(), diagnostics.code_id())
        row("other-code", "fault", hub.now(), "another-code")
        with hub.LOCK:
            self.assertEqual([w for w in hub.health_view()["warnings"] if w["kind"] == "hub_fault"], [])
        answer = self.request("/ui/diagnostics?db=test-generation")[1]
        self.assertEqual(len(answer["faults"]), 1)                 # the old one of this code, within its 30 days
        self.assertEqual([r["tool"] for r in answer["refusals"]], ["read_messages"])

    def test_the_route_answers_only_tools_of_the_hubs_list(self):
        for sig, tool in (("made-up", "acme_merger"), ("real", "read_messages")):
            hub.ins("INSERT INTO faults(sig,kind,program,name,frames,count,first,last,code) VALUES(?,?,?,?,?,?,?,?,?)",
                    (sig, "refusal", "hub", tool, '[["hub.py",2]]', 1, hub.now(), hub.now(), diagnostics.code_id()))
        refusals = self.request("/ui/diagnostics?db=test-generation")[1]["refusals"]
        self.assertEqual([r["tool"] for r in refusals], ["read_messages"])

    def test_a_tool_of_the_hubs_list_keeps_its_name(self):
        self.assertEqual(hub.known_tool("read_messages"), "read_messages")
        self.assertEqual(hub.known_tool("read_messages_" + canary()), "other")
        self.assertEqual(hub.known_tool(None), "other")

    def test_a_write_that_the_database_refuses_makes_no_new_fault(self):
        hub.ins("DROP TABLE faults")
        try:
            fail_with(KeyError("x"))
        except KeyError:
            diagnostics.record("hub")
        with hub.LOCK:
            hub.fault_flush(hub.now())          # raises nothing
        self.assertEqual(diagnostics.pending(), [])

    def test_the_servers_own_error_handler_and_a_dying_thread_count_their_faults(self):
        server = object.__new__(hub.HubServer)
        try:
            fail_with(KeyError(canary()))
        except KeyError:
            with contextlib.redirect_stderr(io.StringIO()):
                hub.HubServer.handle_error(server, None, ("127.0.0.1", 1))
        self.assertEqual([r["name"] for r in diagnostics.pending()], ["KeyError"])
        try:
            fail_with(ValueError(canary()))
        except ValueError as e:
            args = types.SimpleNamespace(exc_type=ValueError, exc_value=e, exc_traceback=e.__traceback__, thread=None)
        hub.thread_fault(args, default=lambda _args: None)
        hub.thread_fault(types.SimpleNamespace(exc_type=SystemExit, exc_value=SystemExit(), exc_traceback=None,
                                               thread=None), default=lambda _args: None)
        self.assertEqual([r["name"] for r in diagnostics.pending()], ["ValueError"])

    def test_a_body_larger_than_any_route_takes_is_refused_before_it_is_read(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        connection.putrequest("POST", "/ui/command")
        connection.putheader("Content-Length", "99999999999999999999")
        connection.endheaders()
        self.assertEqual(connection.getresponse().status, 413)
        connection.close()
        self.assertEqual([row for row in diagnostics.pending() if row["kind"] == "fault"], [])

    def test_an_address_that_does_not_parse_is_no_route_and_no_fault(self):
        for method in ("GET", "POST"):
            connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
            connection.putrequest(method, "http://[x/", skip_host=True)     # the client would parse it for Host
            connection.putheader("Host", f"127.0.0.1:{self.server.server_port}")
            connection.putheader("Content-Length", "0")
            connection.endheaders()
            self.assertEqual(connection.getresponse().status, 404, method)      # not the board, and no fault
            connection.close()
        self.assertEqual([row for row in diagnostics.pending() if row["kind"] == "fault"], [])

    def test_a_client_that_goes_away_while_its_answer_goes_out_is_no_fault(self):
        class Stub(hub.Handler):
            def __init__(self, fails, answered):
                self.fails, self.started, self.sent, self.path = fails, answered, [], "/ui/state"
            def funnel_refused(self): return False
            def host_allowed(self): return True
            def site_allowed(self): return True
            def gone(self): return False
            def json(self, code, body, headers=None): self.sent.append(code)
            def get(self):
                self.answered = self.started
                raise self.fails
        for error in (TimeoutError("stalled"), ConnectionAbortedError("gone")):
            stub = Stub(error, answered=True)
            stub.do_GET()
            self.assertEqual((stub.sent, diagnostics.pending()), ([], []))
        stub = Stub(TimeoutError("the hub's own call"), answered=False)       # before the answer: the hub's fault
        with contextlib.redirect_stderr(io.StringIO()):
            stub.do_GET()
        self.assertEqual(stub.sent, [500])
        self.assertEqual([row["name"] for row in diagnostics.pending()], ["TimeoutError"])
        # The server's own handler keeps its rule (test_ui_api.ClientGone): a reset or a broken pipe is the client's,
        # and any other error there prints, so it is counted too.
        server = object.__new__(hub.HubServer)
        for error in (ConnectionResetError("x"), ConnectionAbortedError("x")):
            try:
                raise error
            except OSError:
                with contextlib.redirect_stderr(io.StringIO()):
                    hub.HubServer.handle_error(server, None, ("127.0.0.1", 1))
        self.assertEqual([row["name"] for row in diagnostics.pending()], ["ConnectionAbortedError"])

    def test_a_flush_with_nothing_counted_writes_nothing(self):
        with hub.LOCK:
            hub.fault_flush(hub.now())
        self.assertEqual(hub.q("SELECT * FROM faults"), [])


if __name__ == "__main__":
    unittest.main()

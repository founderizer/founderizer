"""The day's error report (errorreports.py, the lane "Error reports"): the owner's switch, off until he turns it on,
and what a hub sends to our side while it is on.

The owner, 16 November 2026, to the picture of Settings › General › Error reports: "Yes, as drawn"
(~/dev/founderizer-plans/feedback-diagnostics-plan.md, Phase 3). He was told what goes: "Error codes, versions and
counts. Never your work, names or keys." Most of these tests are about that line: what must NOT reach a report, and
that nothing goes before he turns it on.

The first classes need no hub. The last one runs the test hub of test_ui_api (OwnerAPI), as test_diagnostics does."""
import contextlib
import http.client
import http.server
import io
import json
import os
import threading
import unittest
import unittest.mock

import diagnostics
import errorreports
import hub
import owner_mcp
from test_diagnostics import canary, fail_with, strings
from test_ui_api import OwnerAPI
from leftovers import ROOT, TEST_DIR

HERE = os.path.relpath(os.path.join(TEST_DIR, os.path.basename(__file__)), ROOT)     # as diagnostics names it
FOLDER = os.path.relpath(TEST_DIR, ROOT)          # "." here, "tests" in a clone of the published repository
FLEET = "0123456789abcdef"
NOW = 1_794_000_000.0


def a_fault(**changes):
    return dict({"program": "hub", "class": "KeyError", "frames": [{"file": "hub.py", "line": 120}], "errno": None,
                 "http": None, "count": 2, "first": NOW - 100, "last": NOW - 10}, **changes)


def a_refusal(**changes):
    return dict({"tool": "send_message", "file": "hub.py", "line": 300, "count": 1, "first": NOW - 50,
                 "last": NOW - 5}, **changes)


def report(view, since=0, **facts):
    given = dict(fleet=FLEET, version="2026.11.538", system="Ubuntu 24.04", code="ab12cd", agents=3, servers=2)
    given.update(facts)
    return errorreports.report(given["fleet"], given["version"], given["system"], given["code"], given["agents"],
                               given["servers"], view, since)


class Report(unittest.TestCase):
    def test_the_report_holds_the_contract_keys_and_nothing_else(self):
        body = report({"faults": [a_fault()], "refusals": [a_refusal()]})
        self.assertEqual(set(body), {"fleet", "from", "version", "system", "code", "agents", "servers", "faults",
                                     "refusals"})
        self.assertEqual((body["from"], body["fleet"], body["agents"], body["servers"]), ("hub", FLEET, 3, 2))
        self.assertEqual(set(body["faults"][0]), {"program", "class", "frames", "errno", "http", "count", "first",
                                                  "last"})
        self.assertEqual(set(body["refusals"][0]), {"tool", "file", "line", "count", "first", "last"})

    def test_a_value_out_of_shape_is_left_out(self):
        body = report({"faults": [a_fault(), a_fault(**{"class": "Key Error"}),
                                  a_fault(frames=[{"file": "/Users/ana/hub.py", "line": 3}]),
                                  a_fault(frames=[{"file": "hub.py", "line": -3}]), a_fault(program="helper"),
                                  a_fault(errno=-1), a_fault(http=99), a_fault(count=0), a_fault(first="yesterday"),
                                  a_fault(frames=[{"file": "hub.py", "line": 1, "text": "words"}]), a_fault(frames=[])],
                       "refusals": [a_refusal(tool="send message"), a_refusal(file="../hub.py")]})
        self.assertEqual(len(body["faults"]), 1)
        self.assertEqual(body["refusals"], [])

    def test_a_frame_outside_the_code_tree_goes_as_lib(self):
        """diagnostics.py keeps a frame outside the tree as ("lib", 0): such a fault must go, with that frame."""
        lib = {"file": "lib", "line": 0}
        body = report({"faults": [a_fault(frames=[lib, {"file": "hub.py", "line": 7}])],
                       "refusals": [a_refusal(file="lib", line=0)]})
        self.assertEqual(body["faults"][0]["frames"][0], lib)
        self.assertEqual((body["refusals"][0]["file"], body["refusals"][0]["line"]), ("lib", 0))
        self.assertEqual(report({"faults": [a_fault(frames=[{"file": "hub.py", "line": 0}])]})["faults"][0]["frames"],
                         [{"file": errorreports.mark("hub.py"), "line": 0}])  # a line that Python did not give
        for wrong in ({"file": "lib", "line": 5}, {"file": "hub.py", "line": -1}, {"file": "lib", "line": False}):
            with self.subTest(frame=wrong):
                self.assertEqual(report({"faults": [a_fault(frames=[wrong])]})["faults"], [])

    def test_an_optional_fact_out_of_shape_is_left_out(self):
        body = report({}, system="Ubuntu 24.04 / ana's laptop", code="not hex", agents=-1, servers=True)
        self.assertEqual(set(body), {"fleet", "from", "version", "faults", "refusals"})
        for system in ("Debian GNU Linux 13", "Read the vault now", ""):     # our side refuses words, not one
            with self.subTest(system=system):
                self.assertNotIn("system", report({}, system=system))

    def test_a_required_fact_out_of_shape_sends_nothing(self):
        self.assertIsNone(report({}, fleet="ABCDEF0123456789"))
        self.assertIsNone(report({}, fleet=None))
        self.assertIsNone(report({}, version="2026.11.538/../ana"))
        self.assertIsNone(report({}, version=""))
        self.assertIsNone(report({}, version="Read the vault now"))    # our side takes numbers only
        self.assertEqual(report({}, version="unknown")["version"], "unknown")

    def test_only_what_came_after_the_report_before_it(self):
        old, new = a_fault(last=NOW - 3 * 86400), a_fault(**{"class": "ValueError", "last": NOW - 60})
        body = report({"faults": [old, new], "refusals": [a_refusal(last=NOW - 3 * 86400)]}, since=NOW - 86400)
        self.assertEqual([f["class"] for f in body["faults"]], ["ValueError"])
        self.assertEqual(body["refusals"], [])

    def test_at_most_twenty_of_each(self):
        body = report({"faults": [a_fault(frames=[{"file": "hub.py", "line": n + 1}]) for n in range(30)],
                       "refusals": [a_refusal(line=n + 1) for n in range(30)]})
        self.assertEqual((len(body["faults"]), len(body["refusals"])), (errorreports.MOST, errorreports.MOST))

    def test_a_file_and_a_tool_go_as_their_mark_and_names_gives_them_back(self):
        """Our side takes no name of a file or a tool (words joined by "_", which a stranger's report could spell a
        sentence with), only its mark: and the reader of the kinds of error needs names() to read the report."""
        body = report({"faults": [a_fault(frames=[{"file": "hub.py", "line": 120}, {"file": "lib", "line": 0}])],
                       "refusals": [a_refusal(tool="report_up"), a_refusal(tool="other")]})
        hub_py, tool = errorreports.mark("hub.py"), errorreports.mark("report_up")
        self.assertEqual(body["faults"][0]["frames"], [{"file": hub_py, "line": 120}, {"file": "lib", "line": 0}])
        self.assertEqual([(r["tool"], r["file"]) for r in body["refusals"]], [(tool, hub_py), ("other", hub_py)])
        self.assertTrue(errorreports.MARK.fullmatch(hub_py) and errorreports.MARK.fullmatch(tool))
        text = json.dumps(body)
        self.assertNotIn("hub.py", text)
        self.assertNotIn("report_up", text)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(errorreports.main(["names"]), 0)
        lines = set(out.getvalue().splitlines())
        for line in (f"{hub_py} hub.py", f"{tool} report_up"):        # a file of the tree, a tool of hub.TOOLS
            self.assertIn(line, lines)

    def test_a_stall_goes_as_a_fault_of_its_kind_after_the_faults(self):
        """The owner's "Yes, reports only" of 21 November 2026: each stall of the view goes as a fault of its kind's class,
        with its places as marks and no value, and a run of stalls never pushes a real fault out of the twenty."""
        stall = {"kind": "hold", "frames": [{"file": "hub.py", "line": 5574}, {"file": "lib", "line": 0}],
                 "count": 1, "first": NOW - 300, "last": NOW - 60}
        body = report({"faults": [a_fault()], "stalls": [stall] + [dict(stall, kind=k) for k in ("busy", "collect",
                                                                                                    "paused", "slow")]})
        self.assertEqual([f["class"] for f in body["faults"]],
                         [a_fault()["class"], "StallHold", "StallBusy", "StallCollect", "StallPaused"])
        self.assertEqual(body["faults"][1], {"program": "hub", "class": "StallHold", "errno": None, "http": None,
                                             "frames": [{"file": errorreports.mark("hub.py"), "line": 5574},
                                                        {"file": "lib", "line": 0}],
                                             "count": 1, "first": NOW - 300, "last": NOW - 60})
        many = report({"faults": [a_fault()], "stalls": [stall] * 30})["faults"]
        self.assertEqual((len(many), many[0]["class"]), (errorreports.MOST, a_fault()["class"]))
        with unittest.mock.patch.object(errorreports, "LIMIT", 1500):     # past the size, stalls go before an older fault
            cut = report({"faults": [a_fault(last=NOW - 3000)], "stalls": [stall] * 10})["faults"]
        self.assertEqual((cut[0]["class"], len(cut) < 11), (a_fault()["class"], True))
        self.assertEqual(set(errorreports.STALL_CLASSES), set(diagnostics.STALLS))

    def test_our_side_takes_each_class_of_the_recorder(self):
        """Our side refuses a whole report whose class it does not hold (founderizer-web, src/lib/errors.ts, CLASSES).
        A class added to diagnostics.CLASSES goes there first, then to errorreports.THEIR_CLASSES; so do the classes
        of a stall's kinds (STALL_CLASSES)."""
        self.assertEqual(diagnostics.CLASSES | set(errorreports.STALL_CLASSES.values()), errorreports.THEIR_CLASSES,
                         "a class of diagnostics.CLASSES goes to founderizer-web's src/lib/errors.ts CLASSES first, live "
                         "on the site, and only then to errorreports.THEIR_CLASSES: until then it goes as \"other\"")
        with unittest.mock.patch.object(errorreports, "THEIR_CLASSES", frozenset({"ValueError"})):
            self.assertEqual(report({"faults": [a_fault()]})["faults"][0]["class"], "other")

    def test_a_class_that_code_chose_never_goes(self):
        body = report({"faults": [a_fault(**{"class": "AnaPerez"}), a_fault(**{"class": "other"})]})
        self.assertEqual([f["class"] for f in body["faults"]], ["other"])

    def test_a_view_of_another_shape_gives_an_empty_report(self):
        self.assertEqual((report({"faults": 5, "refusals": "x"})["faults"], report(None)["refusals"]), ([], []))

    def test_a_report_never_passes_the_size_that_our_side_takes(self):
        long = "/".join(["a" * 80] * 4) + ".py"         # the longest file name of diagnostics.FILE
        faults = [a_fault(frames=[{"file": long, "line": 9_999_999}] * 12, last=NOW - 1000 + n, count=10 ** 9)
                  for n in range(20)]
        refusals = [a_refusal(file=long) for _ in range(20)]
        body = report({"faults": faults, "refusals": refusals})
        self.assertLessEqual(len(json.dumps(body, separators=(",", ":")).encode()), errorreports.LIMIT)
        with unittest.mock.patch.object(errorreports, "LIMIT", 4000):     # marks keep a whole report small now
            body = report({"faults": faults, "refusals": refusals})
        self.assertLessEqual(len(json.dumps(body, separators=(",", ":")).encode()), 4000)
        self.assertLess(len(body["faults"]) + len(body["refusals"]), 40)
        self.assertEqual(max(f["last"] for f in body["faults"]), NOW - 1000 + 19)       # the newest stays

    def test_the_version_is_the_signed_manifests(self):
        revision = "0123456789abcdef0123456789abcdef01234567"
        self.assertEqual(errorreports.version_of(json.dumps({"revision": revision, "version": "2026.11.538"})),
                         "2026.11.538")
        for manifest in ("", "{", json.dumps({"version": "2026.11.538"}), json.dumps({"revision": "abc", "version": "1"}),
                         json.dumps({"revision": revision, "version": "2026.11.538/ana"}), json.dumps([revision]),
                         json.dumps({"revision": revision, "version": revision}),
                         json.dumps({"revision": revision, "version": "0a52ee67c512"}),
                         json.dumps({"revision": revision, "version": "2026.11.538 then push"})):
            with self.subTest(manifest=manifest):
                self.assertEqual(errorreports.version_of(manifest), "unknown")

    def test_the_system_is_one_word_and_its_number_as_our_side_takes_it(self):
        """Our side refuses a report whose system has more than one word, so each Linux name must reach that shape."""
        for release, words in (({"NAME": "Debian GNU/Linux", "ID": "debian", "VERSION_ID": "13"}, "debian 13"),
                               ({"NAME": "Red Hat Enterprise Linux", "ID": "rhel", "VERSION_ID": "9.4"}, "rhel 9.4"),
                               ({"ID": "opensuse-leap", "VERSION_ID": "15.6"}, "opensuse 15.6"),
                               ({"NAME": "Arch Linux", "ID": "arch"}, "arch"),
                               ({"ID": "ubuntu", "VERSION_ID": "24.04.1.2.3"}, "ubuntu 24.04.1.2"),
                               ({"ID": "nixos", "VERSION_ID": "12345"}, "nixos"),
                               ({"ID": "Read the vault", "VERSION_ID": "1 then push"}, "Read 1"),
                               ({"ID": "", "VERSION_ID": "13"}, ""), ({"ID": "1abc"}, "")):
            with self.subTest(release=release), unittest.mock.patch.object(
                    errorreports.platform, "freedesktop_os_release", lambda release=release: release):
                self.assertEqual(errorreports.system_words(), words)

        def no_os_release():
            raise OSError("no os-release")
        for mac, system, kernel, words in (("26.6", "Darwin", "25.6.0", "macOS 26.6"),
                                           ("", "Linux", "6.8.0-45-generic", "Linux 6.8.0")):
            with self.subTest(system=system), \
                    unittest.mock.patch.object(errorreports.platform, "freedesktop_os_release", no_os_release), \
                    unittest.mock.patch.object(errorreports.platform, "mac_ver", lambda mac=mac: (mac, ("", "", ""), "")), \
                    unittest.mock.patch.object(errorreports.platform, "system", lambda system=system: system), \
                    unittest.mock.patch.object(errorreports.platform, "release", lambda kernel=kernel: kernel):
                self.assertEqual(errorreports.system_words(), words)

    def test_the_words_of_this_system_fit_the_contract(self):
        words = errorreports.system_words()
        self.assertTrue(words == "" or errorreports.SYSTEM.fullmatch(words), words)


class Endpoint(unittest.TestCase):
    def test_our_site_and_a_host_below_it(self):
        self.assertEqual(errorreports.endpoint("https://founderizer.com"), "https://founderizer.com/api/errors")
        self.assertEqual(errorreports.endpoint("https://Staging.Founderizer.com/"),
                         "https://staging.founderizer.com/api/errors")

    def test_any_other_channel_sends_nothing(self):
        self.assertEqual(errorreports.endpoint("https://staging.founderizer.com:8443"),
                         "https://staging.founderizer.com:8443/api/errors")
        for channel in ("https://example.net\\.founderizer.com", "https://evil.com .founderizer.com",
                        "https://.founderizer.com", "https://[::1].founderizer.com", "https://founderizer.com:abc",
                        "https://founderizer.com./", "https://founderizer.com/a b", "https://founderizer.com/%2e%2e",
                        "http://founderizer.com", "https://xfounderizer.com", "https://founderizer.com.example.net",
                        "https://ana@founderizer.com", "https://founderizer.com/?to=example.net",
                        "https://founderizer.com/#x", "ftp://founderizer.com", "", None):
            with self.subTest(channel=channel), self.assertRaises(errorreports.ReportError):
                errorreports.endpoint(channel)


class Due(unittest.TestCase):
    def test_nothing_goes_while_it_is_off(self):
        self.assertFalse(errorreports.due(False, None, None, None, NOW))

    def test_once_a_day(self):
        self.assertTrue(errorreports.due(True, None, None, None, NOW))
        self.assertFalse(errorreports.due(True, NOW - 3600, NOW - 3600, None, NOW))
        self.assertTrue(errorreports.due(True, NOW - errorreports.DAY, NOW - errorreports.DAY, None, NOW))

    def test_a_try_that_did_not_go_waits_an_hour(self):
        self.assertFalse(errorreports.due(True, None, NOW - 60, None, NOW))
        self.assertTrue(errorreports.due(True, None, NOW - errorreports.RETRY, None, NOW))
        self.assertFalse(errorreports.due(True, NOW - 2 * errorreports.DAY, NOW - 60, None, NOW))

    def test_a_time_from_a_clock_that_was_ahead_counts_as_none(self):
        year = 365 * errorreports.DAY
        self.assertTrue(errorreports.due(True, NOW + year, NOW + year, None, NOW))
        self.assertTrue(errorreports.due(True, None, None, NOW + year, NOW))

    def test_our_sides_hold(self):
        self.assertFalse(errorreports.due(True, None, None, NOW + 60, NOW))
        self.assertTrue(errorreports.due(True, None, None, NOW - 1, NOW))


class Site(http.server.BaseHTTPRequestHandler):
    """A stand-in for our side: it keeps each request and gives the answer that the test set."""

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.seen.append((self.path, dict(self.headers), body))
        code, headers = self.server.answer
        self.send_response(code)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = do_POST            # a redirect that were followed would come back as a GET, and be seen

    def log_message(self, *args):
        pass


class Send(unittest.TestCase):
    def setUp(self):
        self.site = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Site)
        self.site.seen, self.site.answer = [], (200, {})
        thread = threading.Thread(target=self.site.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(self.site.server_close)
        self.addCleanup(self.site.shutdown)
        self.url = f"http://127.0.0.1:{self.site.server_port}/api/errors"

    def test_a_report_that_our_side_takes(self):
        body = report({"faults": [a_fault()]})
        self.assertIsNone(errorreports.send(self.url, body))
        ((path, headers, sent),) = self.site.seen
        self.assertEqual((path, json.loads(sent)), ("/api/errors", body))
        self.assertEqual(headers.get("Content-Type"), "application/json")
        self.assertNotIn("Authorization", headers)

    def test_a_429_names_when_to_try_again(self):
        self.site.answer = (429, {"Retry-After": "120"})
        with self.assertRaises(errorreports.ReportError) as caught:
            errorreports.send(self.url, report({}))
        self.assertEqual((caught.exception.retry_after, caught.exception.status), (120, 429))

    def test_a_redirect_is_an_answer_and_never_a_second_request(self):
        self.site.answer = (302, {"Location": f"http://127.0.0.1:{self.site.server_port}/elsewhere"})
        with self.assertRaises(errorreports.ReportError):
            errorreports.send(self.url, report({}))
        self.assertEqual([p for p, _, _ in self.site.seen], ["/api/errors"])

    def test_an_answer_that_is_not_http_is_a_failed_send(self):
        with unittest.mock.patch.object(errorreports.urllib.request.OpenerDirector, "open",
                                        side_effect=http.client.BadStatusLine("x")):
            with self.assertRaises(errorreports.ReportError) as caught:
                errorreports.send(self.url, report({}))
        self.assertIsNone(caught.exception.retry_after)

    def test_a_refusal_and_no_site(self):
        for status in (400, 404, 413, 503):
            self.site.answer = (status, {})
            with self.subTest(status=status), self.assertRaises(errorreports.ReportError) as caught:
                errorreports.send(self.url, report({}))
            self.assertEqual((caught.exception.status, caught.exception.retry_after), (status, errorreports.DAY))
        with self.assertRaises(errorreports.ReportError) as caught:
            errorreports.send("http://127.0.0.1:1/api/errors", report({}), timeout=5)
        self.assertIsNone(caught.exception.retry_after)         # not reached: tried again after RETRY


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for case in (Report, Endpoint, Due, Send):
        suite.addTests(loader.loadTestsFromTestCase(case))
    suite.addTests(OnTheHub(name) for name in OnTheHub.__dict__ if name.startswith("test_"))
    return suite


class OnTheHub(OwnerAPI):
    def setUp(self):
        super().setUp()
        diagnostics.pending()
        # As test_diagnostics: a checkout of the hub's own, and an empty `~/.fleet` of this test.
        kit = os.path.join(self.tmp.name, "kit")
        os.makedirs(os.path.join(kit, "profiles"))
        with open(os.path.join(kit, "team.json"), "w") as f:
            json.dump(hub.TEAM, f)
        hub.CFG["team_path"] = os.path.join(kit, "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        self.sent = []
        patcher = unittest.mock.patch.object(errorreports, "send", lambda url, body, timeout=None:
                                             self.sent.append((url, body)))
        patcher.start()
        self.addCleanup(patcher.stop)
        channel = unittest.mock.patch.object(hub, "release_channel", lambda: "https://founderizer.com")
        channel.start()
        self.addCleanup(channel.stop)

    def sweep(self, t0):
        with hub.LOCK:
            hub.error_report_sweep(t0)
        thread = hub._error_report["thread"]
        if thread is not None:
            thread.join(10)

    def switch(self, on):
        code, answer = self.request("/ui/error-reports", self.command(send=on))
        self.assertEqual(code, 200, answer)

    def test_off_until_the_owner_turns_it_on(self):
        self.assertIn("error_reports", hub.UI_FEATURES)
        self.assertEqual(self.request("/ui/error-reports?db=test-generation"),
                         (200, {"send": False, "db": "test-generation"}))
        self.sweep(hub.now())
        self.assertEqual(self.sent, [])

    def test_the_owners_switch(self):
        self.switch(True)
        self.assertTrue(self.request("/ui/error-reports?db=test-generation")[1]["send"])
        self.switch(False)
        self.assertFalse(self.request("/ui/error-reports?db=test-generation")[1]["send"])

    def test_a_send_that_is_not_true_or_false_is_refused(self):
        for value in ("yes", 1, None):
            with self.subTest(value=value):
                self.assertEqual(self.request("/ui/error-reports", self.command(send=value))[0], 400)
        self.assertFalse(hub.error_reports_on())

    def test_another_address_and_another_hub_are_refused(self):
        self.assertEqual(self.request("/ui/error-reports", self.command(send=True), source="127.0.0.9")[0], 403)
        self.assertEqual(self.request("/ui/error-reports?db=test-generation", source="127.0.0.9")[0], 403)
        self.assertEqual(self.request("/ui/error-reports?db=another")[0], 409)
        self.assertEqual(self.request("/ui/error-reports")[0], 409)
        self.assertFalse(hub.error_reports_on())

    def test_no_tool_of_the_owners_mcp_server_turns_it_on(self):
        self.assertIn("/ui/error-reports", owner_mcp.NOT_TOOLS)
        with open(owner_mcp.__file__) as f:
            whole = f.read()
        start = whole.index("NOT_TOOLS = {")
        rest = whole[:start] + whole[whole.index("\n}\n", start):]
        self.assertNotIn("/ui/error-reports", rest)

    def test_the_days_report_goes_once_a_day_while_it_is_on(self):
        self.switch(True)
        t0 = hub.now()
        self.sweep(t0)
        ((url, body),) = self.sent
        self.assertEqual(url, "https://founderizer.com/api/errors")
        self.assertEqual((body["from"], body["fleet"]), ("hub", hub.fleet_id()))
        self.assertEqual(body["agents"], len(hub.TEAM.get("agents") or {}))
        self.sweep(t0 + 60)
        self.sweep(t0 + errorreports.RETRY + 1)         # the day's report went: no second one before the DAY
        self.assertEqual(len(self.sent), 1)
        self.sweep(t0 + errorreports.DAY + 1)
        self.assertEqual(len(self.sent), 2)
        self.switch(False)
        self.sweep(t0 + 3 * errorreports.DAY)
        self.assertEqual(len(self.sent), 2)

    def fault(self, words):
        try:
            fail_with(KeyError(words))
        except KeyError:
            with contextlib.redirect_stderr(io.StringIO()):
                hub.print_fault()
        with hub.LOCK:
            hub.fault_flush(hub.now())

    def test_a_real_fault_reaches_the_report_with_no_words(self):
        words = canary()
        self.switch(True)
        self.fault(words)
        self.sweep(hub.now())
        ((_, body),) = self.sent
        (fault,) = body["faults"]
        self.assertEqual(fault["class"], "KeyError")
        files = [f["file"] for f in fault["frames"]]
        self.assertEqual((files[-1], errorreports.mark(HERE) in files),               # fail_with's, called here
                         (errorreports.mark(os.path.normpath(os.path.join(FOLDER, "test_diagnostics.py"))), True))
        text = json.dumps(body)
        for piece in words.split(" "):
            self.assertNotIn(piece, text)
        for value in strings(body):            # no path, but the folder of these tests in a clone
            self.assertNotIn("/", value.removeprefix(FOLDER + "/") if FOLDER != "." else value)

    def test_a_fault_from_before_the_switch_does_not_go(self):
        self.fault(canary())
        self.switch(True)
        t0 = hub.now()
        self.sweep(t0)
        self.assertEqual(self.sent[-1][1]["faults"], [])
        self.fault(canary())
        self.sweep(t0 + errorreports.DAY + 1)
        self.assertEqual([f["class"] for f in self.sent[-1][1]["faults"]], ["KeyError"])

    def test_a_mark_from_a_clock_that_was_ahead_loses_no_fault(self):
        self.switch(True)
        self.fault(canary())
        t0 = hub.now()
        with hub.LOCK:
            hub.kv_set("error_reports_sent", repr(t0 + 2 * errorreports.DAY))
        self.sweep(t0)
        self.assertEqual([f["class"] for f in self.sent[-1][1]["faults"]], ["KeyError"])

    def test_a_yes_from_a_clock_that_was_ahead_sends_nothing_from_before_now(self):
        self.fault(canary())
        self.switch(True)
        t0 = hub.now()
        with hub.LOCK:
            hub.kv_set("error_reports_on_at", repr(t0 + 2 * errorreports.DAY))
        self.sweep(t0)
        self.assertEqual(self.sent[-1][1]["faults"], [])

    def test_the_version_is_the_releases_and_never_a_commit(self):
        revision = "0123456789abcdef0123456789abcdef01234567"
        manifest = json.dumps({"revision": revision, "version": "2026.11.538"})
        with unittest.mock.patch.object(hub, "git_kit", lambda *a, **k: (0, manifest, "")):
            self.assertEqual(hub.running_version(), "2026.11.538")
        with unittest.mock.patch.object(hub, "git_kit", lambda *a, **k: (128, "", "fatal: no release.json")):
            self.assertEqual(hub.running_version(), "unknown")
        self.switch(True)
        self.sweep(hub.now())
        self.assertNotRegex(self.sent[0][1]["version"], r"^[0-9a-f]{7,40}$")

    def test_a_channel_of_another_site_sends_nothing_for_a_day(self):
        self.switch(True)
        built = []
        body = hub.error_report_body
        t0 = hub.now()
        with unittest.mock.patch.object(hub, "release_channel", lambda: "https://example.net"), \
                unittest.mock.patch.object(hub, "error_report_body", lambda since: built.append(since) or body(since)), \
                contextlib.redirect_stdout(io.StringIO()):
            self.sweep(t0)
            self.sweep(t0 + errorreports.RETRY + 1)
        self.assertEqual((self.sent, built), ([], []))
        self.assertIsNone(hub.kv_time("error_reports_sent"))
        self.assertGreaterEqual(hub.kv_time("error_reports_hold"), t0 + errorreports.DAY)

    def test_a_refusal_of_our_side_holds_a_day(self):
        self.switch(True)

        def refused(url, body, timeout=None):
            raise errorreports.ReportError("founderizer.com answered 400", retry_after=errorreports.DAY, status=400)

        t0 = hub.now()
        with unittest.mock.patch.object(errorreports, "send", refused), contextlib.redirect_stdout(io.StringIO()):
            self.sweep(t0)
        self.sweep(t0 + errorreports.RETRY + 1)
        self.assertEqual(self.sent, [])
        self.sweep(hub.kv_time("error_reports_hold") + 1)
        self.assertEqual(len(self.sent), 1)

    def test_a_report_that_the_owner_turned_off_before_it_left_does_not_go(self):
        self.switch(True)
        with hub.LOCK:
            body = hub.error_report_body(0)
        self.switch(False)
        hub.error_report_send("https://founderizer.com/api/errors", body, repr(hub.now()))
        self.assertEqual(self.sent, [])

    def test_a_step_that_raises_is_tried_again_only_after_an_hour(self):
        self.switch(True)
        calls = []

        def broken(since):
            calls.append(since)
            raise RuntimeError("a step of the body raised")

        t0 = hub.now()
        with unittest.mock.patch.object(hub, "error_report_body", broken):
            for t in (t0, t0 + 5, t0 + 60):
                with contextlib.suppress(RuntimeError):
                    self.sweep(t)
        self.assertEqual(len(calls), 1)
        self.assertEqual(hub.kv_time("error_reports_tried"), t0)

    def test_the_hubs_own_times_wake_no_app(self):
        for key in ("error_reports_tried", "error_reports_sent", "error_reports_hold", "error_reports_on_at"):
            self.assertIn(key, hub.QUIET_KEYS)
        self.assertNotIn("error_reports", hub.QUIET_KEYS)       # the owner's switch is news for every app

    def test_our_sides_hold_waits(self):
        self.switch(True)

        wait = 5 * 3600         # longer than RETRY, so that only the hold keeps the next try back

        def held(url, body, timeout=None):
            raise errorreports.ReportError("founderizer.com answered 429", retry_after=wait, status=429)

        t0 = hub.now()
        with unittest.mock.patch.object(errorreports, "send", held), contextlib.redirect_stdout(io.StringIO()):
            self.sweep(t0)
        self.assertGreaterEqual(hub.kv_time("error_reports_hold"), t0 + wait)
        self.sweep(t0 + errorreports.RETRY + 1)
        self.assertEqual(self.sent, [])
        self.assertIsNone(hub.kv_time("error_reports_sent"))
        self.sweep(hub.kv_time("error_reports_hold") + 1)
        self.assertEqual(len(self.sent), 1)

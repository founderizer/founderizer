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
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import uuid

import diagnostics
import errorreports
import hub
import owner_mcp
import releases
from test_diagnostics import canary, fail_with, strings
from test_ui_api import OwnerAPI
from leftovers import ROOT, TEST_DIR, parent_pipe

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


def report(view, since=0, health=None, **facts):
    given = dict(fleet=FLEET, version="2026.11.538", system="Ubuntu 24.04", code="ab12cd", agents=3, servers=2)
    given.update(facts)
    return errorreports.report(given["fleet"], given["version"], given["system"], given["code"], given["agents"],
                               given["servers"], view, since, health=health)


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
        # the platform's own host since 21 November 2026: a channel there must not stop the fleet's reports
        self.assertEqual(errorreports.endpoint("https://platform.founderizer.com"),
                         "https://platform.founderizer.com/api/errors")

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

    def test_an_early_report_goes_at_once_and_at_most_four_times_a_day(self):
        """The plan's 3.3: a report goes early when the hub asks for one, at most EARLY_MOST in a DAY, and never past
        our side's hold or a try that just failed. A check that turns bad and good again each minute would else send a
        report each minute, and our side's count of one fleet would refuse its reports for the hour."""
        sent, day = NOW - 3600, errorreports.DAY
        self.assertEqual(errorreports.due(True, sent, sent, None, NOW), None)
        self.assertEqual(errorreports.due(True, sent, sent, None, NOW, NOW - 5), "early")
        four = [NOW - 60 * i for i in range(1, errorreports.EARLY_MOST + 1)]
        self.assertIsNone(errorreports.due(True, sent, sent, None, NOW, NOW - 5, four))
        self.assertEqual(errorreports.due(True, sent, sent, None, NOW, NOW - 5, [NOW - day - 1] + four[1:]), "early")
        self.assertIsNone(errorreports.due(True, sent, sent, NOW + 60, NOW, NOW - 5))
        self.assertIsNone(errorreports.due(True, sent, NOW - 60, None, NOW, NOW - 5))
        self.assertIsNone(errorreports.due(False, sent, sent, None, NOW, NOW - 5))
        self.assertEqual(errorreports.due(True, NOW - day, NOW - day, None, NOW, NOW - 5, four), "day")
        # a clock that went back an hour after four early reports: they are ahead of it, and still count
        self.assertIsNone(errorreports.due(True, sent, sent, None, NOW - 3600, NOW - 3605, four))


# The keys of the health block, as our side requires each one (founderizer-web, tests/fixtures/error-reports/
# hub-health-w16.json and docs/CONTRACTS.md, "The health of a fleet").
HEALTH_KEYS = {"release": {"newest", "state", "step", "cause", "tries", "since", "behind", "channel"},
               "check": {"code", "hub", "servers", "since", "repairs", "repaired"},
               "machine": {"memory", "swap", "cores", "ooms", "starts"}}


def a_release(**changes):
    return dict({"newest": "2026.11.762", "state": "failed", "step": "fetch", "cause": "no_ipv4_route", "tries": 3,
                 "since": NOW - 600, "behind": 2, "channel": 200}, **changes)


def a_machine(**changes):
    return dict({"memory": 1907, "swap": 2047, "cores": 1, "ooms": 3, "starts": 2}, **changes)


class HealthBlock(unittest.TestCase):
    def test_the_block_has_the_contracts_keys_and_words_and_nothing_else(self):
        """Our side requires every key of the block and takes only the words of its lists (W16): a key left out, or a
        word that the copy did not check, is a 400, and the block then waits a day. A word of no list goes as "other",
        a count above our side's bound as the bound, a second check of one code is left out, and a version that is not
        one holds the whole block back."""
        block = errorreports.health(
            a_release(state="downloading", step="unpack", cause="cosmic_ray", tries=10 ** 9),
            [{"code": "disk", "hub": False, "servers": 1, "since": NOW - 60}, {"code": "disk", "hub": True,
                                                                               "servers": 0, "since": None},
             {"code": "eth0_link", "hub": None, "servers": 0, "since": None}, {"code": "ssh", "hub": "yes",
                                                                               "servers": 0, "since": None}],
            a_machine(memory=10 ** 8))
        self.assertEqual(set(block), {"release", "checks", "machine"})
        self.assertEqual(set(block["release"]), HEALTH_KEYS["release"])
        self.assertEqual([set(c) for c in block["checks"]], [HEALTH_KEYS["check"]] * 2)
        self.assertEqual(set(block["machine"]), HEALTH_KEYS["machine"])
        self.assertEqual((block["release"]["state"], block["release"]["step"], block["release"]["cause"],
                          block["release"]["tries"]), ("other", "other", "other", errorreports.NUMBER_MOST))
        self.assertEqual([(c["code"], c["hub"], c["repairs"], c["repaired"]) for c in block["checks"]],
                         [("disk", False, 0, 0), ("other", None, 0, 0)])
        self.assertEqual(block["machine"]["memory"], errorreports.MB_MOST)
        self.assertEqual(errorreports.health(a_release(step=None, cause=None), [], a_machine())["release"]
                         ["cause"], "none")
        for wrong in (a_release(newest="2026.11.762 (abc)"), a_release(tries=-1), a_release(newest=None)):
            with self.subTest(release=wrong):
                self.assertIsNone(errorreports.health(wrong, [], a_machine()))
        self.assertIsNone(errorreports.health(a_release(), [], a_machine(cores=0)))
        body = report({}, health=errorreports.health(a_release(), [], a_machine()))
        self.assertEqual(body["health"]["release"]["newest"], "2026.11.762")

    def test_each_copy_is_our_sides_list_as_it_is_today(self):
        """Each copy is our side's list (founderizer-web, src/lib/errors.ts, HEALTH_WORDS of 21 November 2026, with the
        codes of the hub's own warnings of 22 November 2026), word for word. A word comes to our side first, and only
        then into a copy and here: a hub whose copy took a word that our side does not have would have each report
        with the block refused, at each fleet, each day. A new word of the hub's own goes as "other" until both sides
        take it."""
        theirs = {
            "state": "verified held updating passed kept rolled_back done failed none other",
            "step": "room hold branch clean pinned fetch have already minimum clone merge keep schema selftest verify "
                    "take push follow other",
            "cause": "none no_ipv4_route dns connect tls http timeout memory disk conflict check busy hold branch "
                     "own_changes other",
            "check": "uplink ipv4_route ipv6_route dns channel upstream tailnet clock disk memory oom release_lag "
                     "firewall updates restart quiet egress network ssh npm updates_off macos_update egress_table "
                     "records schema timers release_start helper vault manager_session server_update other"}
        for name, copy in (("state", errorreports.STATES), ("step", errorreports.STEPS),
                           ("cause", errorreports.CAUSES), ("check", errorreports.CHECKS)):
            self.assertEqual(copy, tuple(theirs[name].split()), f"{name}: put a new word on our side first")

    def test_each_word_of_the_hubs_sources_is_in_our_sides_copy(self):
        """A new release state, step or cause, a new key of the server watch, or a new code of the hub's own warnings,
        must reach our side's lists, and so these copies, before a release sends it: else it goes as "other", and
        nobody on our side reads what broke. Each copy ends with "other" and holds each word once, as our side's lists
        do. And each kind of warning that health_view can make is decided once: it goes as its code (WARNING_CODES) or
        never (WARNING_KEPT). Else a new warning whose way out is ours ("Tell us") would never reach our side, and the
        owner would be left with the Report a problem button that F5 asked to make needless."""
        for copy, source in ((errorreports.STATES, hub.RELEASE_STATES + ("none",)),
                             (errorreports.STEPS, releases.STEPS), (errorreports.CAUSES, releases.CAUSES + ("none",)),
                             (errorreports.CHECKS, tuple(hub.WATCH_WORDS) + tuple(hub.WARNING_CODES.values()))):
            with self.subTest(copy=copy[:2]):
                self.assertEqual([w for w in source if w not in copy], [])
                self.assertEqual((copy[-1], len(set(copy))), ("other", len(copy)))
        kinds, sent, kept = warning_kinds(), set(hub.WARNING_CODES), set(hub.WARNING_KEPT)
        self.assertEqual(sorted(kinds - sent - kept), [], "decide: hub.WARNING_CODES or hub.WARNING_KEPT")
        self.assertEqual((sorted(sent & kept), sorted((sent | kept) - kinds)), ([], []))
        self.assertEqual(sorted((set(hub.WARNING_HUB) | set(hub.WARNING_EARLY)) - set(hub.WARNING_CODES.values())), [])
        self.assertIn("manager_down", kinds)     # the reading of the manager's kinds found them
        # The owner's own step never goes: the trust in a server's vault that ends or ended because his Mac did not
        # sign it again (the second read of F5 piece 3, M2: the privacy sentence's "a server's vault is out of date" is
        # not an ended trust, whose vault program is current). A server's update that failed or is behind goes as
        # server_update (the owner's answer to card F5-3), and asks no early report.
        self.assertEqual(sorted({"vault_pin_ends", "vault_pin_ended"} - kept), [])
        self.assertEqual([hub.WARNING_CODES.get(k) for k in ("machine_failed", "machine_behind")], ["server_update"] * 2)
        self.assertNotIn("server_update", hub.WARNING_EARLY)


def warning_kinds():
    """Every kind of warning that hub.health_view can make, read from its code: the first value of each call of its
    warn(), as a word, two words of a condition, or one of the three forms that build a kind there: "machine_" and the
    two update states that its condition names, "manager_" and each kind that manager_flag_update sets, and the kind of
    pin_end_words. Any other form fails here, so that a new one gets its decision too."""
    import ast
    import inspect
    import textwrap

    def tree(fn):
        return ast.parse(textwrap.dedent(inspect.getsource(fn)))

    def words(node):
        """The words of a word, or of a condition between two words, else None."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, ast.IfExp) and all(isinstance(n, ast.Constant) and isinstance(n.value, str)
                                               for n in (node.body, node.orelse)):
            return {node.body.value, node.orelse.value}
        return None

    flags = set()
    for node in ast.walk(tree(hub.manager_flag_update)):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
            if isinstance(target, ast.Tuple) and isinstance(value, ast.Tuple):
                target, value = target.elts[0], value.elts[0]
            if isinstance(target, ast.Name) and target.id == "kind":
                flags |= words(value) or set()
    (pin,) = [n.value.elts[0] for n in ast.walk(tree(hub.pin_end_words)) if isinstance(n, ast.Return)]
    forms = {"'machine_' + m['update']['state']": {"machine_behind", "machine_failed"},
             "'manager_' + flag['kind']": {"manager_" + k for k in flags}, "kind": words(pin)}
    kinds = set()
    for node in ast.walk(tree(hub.health_view)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "warn":
            found = words(node.args[0]) or forms.get(ast.unparse(node.args[0]))
            assert found, f"a new form of a warning's kind: {ast.unparse(node.args[0])}"
            kinds |= found
    return kinds


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
        """A 4xx holds the next report a DAY: the same report would only be refused again. So does a redirect that
        stays (301, 308): the report follows none, so it would meet it again each hour for ever, with a line in the
        hub's log each time, if founderizer.com/api/errors became one. A 5xx or another 3xx (our site, or a deploy of
        it, down for a moment) waits an hour, as a send that did not reach our side does. Until 22 November 2026 a 503
        held a DAY too: one short fault of our site then put two reports 48 hours apart, and our side counts a hub that
        sent nothing for 36 hours as silent (founderizer-web, fleet-health.ts, live_hours)."""
        for status, retry in ((400, errorreports.DAY), (404, errorreports.DAY), (413, errorreports.DAY),
                              (301, errorreports.DAY), (308, errorreports.DAY), (302, errorreports.RETRY),
                              (307, errorreports.RETRY), (500, errorreports.RETRY), (503, errorreports.RETRY)):
            self.site.answer = (status, {})
            with self.subTest(status=status), self.assertRaises(errorreports.ReportError) as caught:
                errorreports.send(self.url, report({}))
            self.assertEqual((caught.exception.status, caught.exception.retry_after), (status, retry))
            self.assertEqual(str(caught.exception), f"127.0.0.1 answered {status}")     # the host that it sent to
        with self.assertRaises(errorreports.ReportError) as caught:
            errorreports.send("http://127.0.0.1:1/api/errors", report({}), timeout=5)
        self.assertIsNone(caught.exception.retry_after)         # not reached: tried again after RETRY


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for case in (Report, Endpoint, Due, HealthBlock, Send, StartAndStop):
        suite.addTests(loader.loadTestsFromTestCase(case))
    for case in (OnTheHub, HealthOnTheHub):
        suite.addTests(case(name) for name in case.__dict__ if name.startswith("test_"))
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
        # no code of a restart, and no version read at HEAD, of an earlier test
        hub._error_report.update(runs=None, code=None, head=None)
        self.addCleanup(hub._error_report.update, runs=None, code=None, head=None)

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
                unittest.mock.patch.object(hub, "error_report_body",
                                           lambda since, **how: built.append(since) or body(since, **how)), \
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

        def broken(since, **how):
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
        for key in ("error_reports_tried", "error_reports_sent", "error_reports_hold", "error_reports_on_at",
                    "error_reports_release", "error_reports_watch", "error_reports_early_at", "error_reports_earlies",
                    "error_reports_health_hold", "error_reports_starts", "error_reports_oom", "error_reports_running",
                    "error_reports_restart", "error_reports_warnings"):
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


class HealthOnTheHub(OnTheHub):
    """The health block on the test hub (W15), with a /proc of the test's own: this Mac has none, and the block goes
    only where one is."""

    def setUp(self):
        super().setUp()
        self.proc = os.path.join(self.tmp.name, "proc")
        os.makedirs(self.proc)
        self.machine(kills=3)
        for name in ("MEMINFO", "VMSTAT", "BOOT_ID"):
            patcher = unittest.mock.patch.object(errorreports, name, os.path.join(self.proc, name.lower()))
            patcher.start()
            self.addCleanup(patcher.stop)
        for patcher in (unittest.mock.patch.object(hub, "HUB_KIND", "linux"),
                        unittest.mock.patch.dict(hub.HUB_LOAD, at=None, load={"disk_used": 1, "disk_total": 10,
                                                                              "memory_used": 1, "memory_total": 10}),
                        unittest.mock.patch.dict(hub.HUB_HARDENING, read=None),
                        unittest.mock.patch.object(hub, "running_version", lambda: "2026.11.700")):
            patcher.start()
            self.addCleanup(patcher.stop)
        hub.TEAM["hub"] = {"machine": "hub"}
        hub._error_report.update(looked=None)

    def machine(self, kills, boot="5d0c9a4e-1f2b-4c3d-8e9f-0a1b2c3d4e5f", extra=""):
        files = {"meminfo": f"MemTotal:        1953124 kB\nMemAvailable:     900000 kB\n{extra}SwapTotal:       "
                            f"2097148 kB\n", "vmstat": f"nr_free_pages 12\noom_kill {kills}\n", "boot_id": boot + "\n"}
        for name, text in files.items():
            with open(os.path.join(self.proc, name), "w") as f:
                f.write(text)

    def release(self, version, state, **columns):
        row = dict({"seen": hub.now(), "revision": uuid.uuid4().hex + uuid.uuid4().hex[:8], "version": version,
                    "state": state}, **columns)
        with hub.LOCK:
            hub.q(f"INSERT INTO releases({','.join(row)}) VALUES({','.join('?' * len(row))})", tuple(row.values()))
        return row

    def look(self, t0):
        with hub.LOCK:
            hub.error_report_look(t0, force=True)
            asked = hub.kv_time("error_reports_early_at")
            hub.kv_set("error_reports_early_at", None)
        return asked

    def health(self):
        with hub.LOCK:
            return hub.error_report_body(0).get("health")

    def watch(self, said):
        with hub.LOCK:
            hub.kv_set("server_watch", json.dumps(said))

    def refusal(self):
        """A refused call of one of the hub's own tools (diagnostics.view keeps no other)."""
        try:
            fail_with(hub.ToolError("a refused call"))
        except hub.ToolError:
            diagnostics.refused("read_messages")
        with hub.LOCK:
            hub.fault_flush(hub.now())

    @staticmethod
    def git(versions):
        """A stand-in for git_kit whose checkout has release.json of `versions` ({revision: version}) at each revision:
        the checkout's HEAD at the new release, and the code that runs at another."""
        def git_kit(*args, **how):
            if args[:2] == ("cat-file", "blob") and args[2].split(":")[0] in versions:
                return 0, json.dumps({"revision": "0" * 40, "version": versions[args[2].split(":")[0]]}), ""
            return 128, "", "fatal"
        return unittest.mock.patch.object(hub, "git_kit", git_kit)

    def test_no_word_of_a_machine_rides_in_the_health(self):
        """The plan's W15 bug (1): every value of the block is a word of a list, a version, a number or a time. A canary
        in each source that the block reads (git's own line and made-up words in a release's row, a host as a server's
        name and its address, words in the server watch's record, the machine's start id and a line of its memory
        file) never reaches the body: a source passed on as it is would carry it to our side, where an agent reads
        what is kept. So for the hub's own warnings (F5 piece 3): an agent's name, a server's name, the database
        check's result, a schema step and the helper's own words of a failed start of the manager are in the words of
        the owner's System status, and only their codes and counts go."""
        host, link, address = f"cnry{uuid.uuid4().hex[:8]}.example.net", f"enp{uuid.uuid4().hex[:6]}s0", "203.0.113.77"
        said = f"fatal: unable to access 'https://{host}/x.git/': Could not resolve host: {host}"
        agent, step, why = f"cnry{uuid.uuid4().hex[:8]}", f"ALTER TABLE {link} ADD COLUMN x", f"exec {address} failed"
        hub.TEAM["addresses"][host] = address
        hub.TEAM["agents"][agent] = {"role": "worker", "runtime": "claude", "machine": host, "can": []}
        with hub.LOCK:
            for key, value in (("integrity", f"*** in database main *** Page 7 of {host}"),
                               ("schema_problems", json.dumps([f"{step}: duplicate column name"])),
                               ("mgr_flag_kind", "down"), ("mgr_flag_since", repr(hub.now())),
                               ("mgr_flag", hub.MANAGER_NOT_RUNNING), ("mgr_start_failed", "1"),
                               ("mgr_start_failed_why", why)):
                hub.kv_set(key, value)
            shown = json.dumps(hub.health_view())
        for piece in (agent, host, step, why):      # each canary is in the words that the owner reads
            self.assertIn(piece, shown)
        self.machine(kills=4, boot=f"{host}-{link}", extra=f"{link}: 5 kB\n")
        row = self.release("2026.11.900", link, step=f"step-{host}", cause=link, says=said, pinned="f" * 40,
                           reached="e" * 40, finished=hub.now())
        self.release(host, "kept", says=said)       # a version that is not one is no release of the block
        with hub.LOCK:
            hub.kv_set("releases_status", f"503 {host}")
        self.watch({host: {"told": ["disk", link], "restart": None}, "hub": {"told": ["firewall", said]}})
        self.switch(True)
        self.sweep(hub.now())
        ((_, body),) = self.sent
        health = body["health"]
        self.assertEqual((health["release"]["newest"], health["release"]["state"], health["release"]["step"],
                          health["release"]["channel"]), ("2026.11.900", "other", "other", 0))
        checks = {c["code"]: c for c in health["checks"]}
        self.assertEqual((checks["disk"]["servers"], checks["firewall"]["hub"]), (1, True))
        self.assertEqual([(checks[code]["hub"], checks[code]["servers"]) for code in
                          ("records", "schema", "manager_session", "helper", "vault", "release_start", "timers",
                           "server_update")],
                         [(True, 0), (True, 0), (True, 0), (True, 1), (False, 0), (False, 0), (False, 0), (False, 0)])
        text = json.dumps(body)
        for piece in (host, link, address, "unable to access", "resolve", row["revision"], "f" * 40, "e" * 40, agent,
                      step, why, "Page 7", "duplicate column", "database"):
            self.assertNotIn(piece, text)

    def test_a_refused_block_sends_the_report_again_at_once_without_it(self):
        """The plan's W15 bug (2): our side answers 400 to a report with the block (a site that does not take it yet,
        or a word that it does not take yet). The same report goes again at once without the block, our side holds
        nothing back, and the block waits a day from the report's stamp: a hub that waited a day would send no faults
        for a day, one that sent the block again at the next report would be refused again, and one whose hold began
        after the stamp would hold the block back from the next day's report too."""
        self.switch(True)
        sends = []

        def site(url, body, timeout=None):
            sends.append(body)
            if "health" in body:
                raise errorreports.ReportError("founderizer.com answered 400", retry_after=errorreports.DAY, status=400)

        t0 = hub.now()
        with unittest.mock.patch.object(errorreports, "send", site), contextlib.redirect_stdout(io.StringIO()):
            self.sweep(t0)
            self.assertEqual(len(sends), 2)
            self.assertIn("health", sends[0])
            self.assertEqual(sends[1], {k: v for k, v in sends[0].items() if k != "health"})
            self.assertEqual((hub.kv_time("error_reports_sent"), hub.kv_time("error_reports_hold"),
                              hub.kv_time("error_reports_health_hold")), (t0, None, t0 + errorreports.DAY))
            with hub.LOCK:
                hub.error_report_early("a test")
            self.sweep(t0 + 60)                 # the next report, early, goes without the block
            self.assertEqual((len(sends), "health" in sends[2]), (3, False))
        with hub.LOCK:
            hub.kv_set("error_reports_health_hold", repr(hub.now() - 1))
        self.assertIsNotNone(self.health())     # a day later the block goes again

    def test_an_owner_who_turns_reports_off_during_the_first_send_gets_no_second(self):
        """The switch is read again before the report goes again without the block: an owner who turned error reports
        off while the first send waited for our side must not get a report that goes after his no."""
        self.switch(True)
        sends = []

        def site(url, body, timeout=None):
            sends.append(body)
            with hub.LOCK:
                hub.set_error_reports(False)
            raise errorreports.ReportError("founderizer.com answered 400", retry_after=errorreports.DAY, status=400)

        with unittest.mock.patch.object(errorreports, "send", site), contextlib.redirect_stdout(io.StringIO()):
            self.sweep(hub.now())
        self.assertEqual([("health" in body) for body in sends], [True])

    def test_a_second_send_that_does_not_go_waits_as_any_send(self):
        """After a 400 to the block, the second send meets our side's answer as any send does: a 429 holds the next
        try for its Retry-After, and a send that does not reach our side is tried again after an hour. Neither marks
        the day as sent, and neither starts the block's counts again: their report was not taken."""
        self.switch(True)
        answers = iter([(400, errorreports.DAY), (429, 120), (400, errorreports.DAY), (None, None)])
        calls = []

        def site(url, body, timeout=None):
            calls.append("health" in body)
            status, retry = next(answers)
            raise errorreports.ReportError("answered", retry_after=retry, status=status)

        counts = hub.kv_get("error_reports_oom")
        t0 = hub.now()
        with unittest.mock.patch.object(errorreports, "send", site), contextlib.redirect_stdout(io.StringIO()):
            self.sweep(t0)
            self.assertTrue(t0 + 100 < hub.kv_time("error_reports_hold") <= hub.now() + 120)
            with hub.LOCK:
                hub.kv_set("error_reports_hold", None)
                hub.kv_set("error_reports_health_hold", None)
            self.sweep(t0 + errorreports.RETRY + 1)
            self.assertIsNone(hub.kv_time("error_reports_hold"))
            self.sweep(t0 + errorreports.RETRY + 60)        # not reached: tried again only after an hour
        self.assertEqual(calls, [True, False, True, False])
        self.assertEqual((hub.kv_time("error_reports_sent"), hub.kv_get("error_reports_oom")), (None, counts))

    def test_one_event_sends_one_early_report(self):
        """At the real clock: the look of a pass asks for an early report after the pass's stamp, and the report that
        answers it ends the ask, so the next pass sends nothing. A report that kept the ask would send a second early
        report 5 seconds later for the same event, and use two of the day's four."""
        self.switch(True)
        self.sweep(hub.now())                   # the day's report, and the first look
        self.watch({"hub": {"told": ["memory"]}})
        hub._error_report["looked"] = None      # the pass's own look, as a minute later
        self.sweep(hub.now())
        self.sweep(hub.now())
        self.assertEqual(len(self.sent), 2)
        self.assertIsNone(hub.kv_time("error_reports_early_at"))

    def test_an_event_during_a_send_keeps_its_ask(self):
        """An event that comes while a report is on its way asks with a new value, so the send ends only the ask that it
        answered, and the event gets its own report. A slow send is most likely when the network breaks, and an ask
        that the send ended would wait for the day's report, up to a day later."""
        self.switch(True)
        self.sweep(hub.now())                   # the day's report
        sends = []

        def site(url, body, timeout=None):
            sends.append(body)
            if len(sends) == 1:
                with hub.LOCK:
                    hub.error_report_early("an event during the send")

        with hub.LOCK:
            hub.error_report_early("a test")
        with unittest.mock.patch.object(errorreports, "send", site):
            self.sweep(hub.now())
            self.assertIsNotNone(hub.kv_time("error_reports_early_at"))
            self.sweep(hub.now())
        self.assertEqual(len(sends), 2)
        self.assertIsNone(hub.kv_time("error_reports_early_at"))

    def test_at_most_four_early_reports_go_in_a_day(self):
        """The plan's cap on the hub: each early report that went counts, so a fifth ask in the day waits. A hub that
        did not count them would send a report for each event, and a check that comes and goes would fill our side's
        count of one fleet."""
        self.switch(True)
        self.sweep(hub.now())
        for _ in range(errorreports.EARLY_MOST + 1):
            with hub.LOCK:
                hub.error_report_early("a test")
            self.sweep(hub.now())
        self.assertEqual(len(self.sent), 1 + errorreports.EARLY_MOST)
        self.assertIsNotNone(hub.kv_time("error_reports_early_at"))      # the fifth waits for its day

    def test_kills_and_starts_count_from_the_last_report_with_the_block_that_our_side_took(self):
        """ooms and starts count since the last report with the block that our side took (the contract's "Since the
        last report"), from what that report held, and from the owner's yes: a hub that sent the kills since the
        machine's start at each report would count each one again every day, one that read /proc again after the send
        would count them again when that read failed, and one that counted from a report that went without the block
        would lose those that it carried. A new start of the machine counts from its own start."""
        self.switch(True)                       # 3 kills before his yes
        self.machine(kills=5)
        for _ in range(2):                      # two starts, each after a stop that the hub planned
            with hub.LOCK:
                hub.error_reports_stopping()
            hub.error_reports_started()

        def site(url, body, timeout=None):
            self.sent.append((url, body))
            os.remove(os.path.join(self.proc, "vmstat"))        # /proc cannot be read once the send is done

        t0 = hub.now()
        with unittest.mock.patch.object(errorreports, "send", site):
            self.sweep(t0)
        self.assertEqual(self.sent[-1][1]["health"]["machine"], {"memory": 1907, "swap": 2047, "cores": os.cpu_count(),
                                                                  "ooms": 2, "starts": 2})
        self.machine(kills=6)

        def refused(url, body, timeout=None):
            if "health" in body:
                raise errorreports.ReportError("answered 400", retry_after=errorreports.DAY, status=400)
            self.sent.append((url, body))

        with unittest.mock.patch.object(errorreports, "send", refused), contextlib.redirect_stdout(io.StringIO()):
            self.sweep(t0 + errorreports.DAY + 1)
        self.assertNotIn("health", self.sent[-1][1])
        with hub.LOCK:
            hub.kv_set("error_reports_health_hold", None)
        self.machine(kills=8)
        self.assertEqual(self.health()["machine"]["ooms"], 3)       # 5 to 8: the report without the block took none
        self.machine(kills=1, boot="0f0e0d0c-1f2b-4c3d-8e9f-0a1b2c3d4e5f")
        self.assertEqual(self.health()["machine"]["ooms"], 1)

    def test_a_report_goes_early_when_the_hubs_server_or_the_hub_breaks(self):
        """The plan's 3.3: a check that turns bad on the hub's own server, a start after a stop that the hub did not
        plan and a start on other code than its restart onto new code went to each send a report before its day; a
        fault that was there before the first look, a fault of another server, a planned stop, a restart that went
        where it was to go, a delivery that moved HEAD after it, and a start by the exec of a restart in place do
        not."""
        self.switch(True)
        t0 = hub.now()
        self.sweep(t0)                          # the day's report, and the first look: its faults were there
        self.watch({"web-1": {"told": ["disk"]}})
        self.assertIsNone(self.look(t0 + 60))
        self.watch({"web-1": {"told": ["disk"]}, "hub": {"told": ["memory"]}})
        self.assertIsNotNone(self.look(t0 + 120))
        hub.error_reports_started()             # main(): the start, and then its stop signal's handler
        hub.error_reports_serving()
        self.assertIsNone(self.look(t0 + 150))
        with hub.LOCK:
            hub.error_reports_stopping()
        hub.error_reports_started()
        hub.error_reports_serving()
        self.assertIsNone(self.look(t0 + 180))  # a planned stop
        hub.error_reports_started()             # no stop came between: the process ended by itself
        self.assertIsNotNone(self.look(t0 + 240))
        # the code that runs after a restart onto "e": other code; the same code after a delivery moved HEAD; "e"
        for runs, same, early in (("d" * 40, False, True), ("d" * 40, True, False), ("e" * 40, False, False)):
            with hub.LOCK:
                hub.kv_set("error_reports_restart", json.dumps({"to": "e" * 40, "at": t0}))
            with unittest.mock.patch.object(hub, "kit_revision", lambda fresh=False: runs), \
                    unittest.mock.patch.object(hub, "same_code", lambda a, b: same):
                hub.error_reports_started()
            self.assertEqual(self.look(t0 + 300) is not None, early, (runs, same))
        with hub.LOCK:
            hub.kv_set("error_reports_running", "1")        # a restart in place whose stop could not take LOCK
        with unittest.mock.patch.dict(hub.SERVING, execed=False), \
                unittest.mock.patch.dict(os.environ, {hub.EXEC_AT: repr(time.time())}):
            hub.code_started()                              # main()'s first step reads the exec
            hub.error_reports_started()
        self.assertIsNone(self.look(t0 + 330))
        with hub.LOCK:
            hub.error_report_early("a test")
        self.sweep(t0 + 360)
        self.assertEqual(len(self.sent), 2)     # the early one went, before the day

    def test_a_release_that_does_not_end_done_sends_the_report_early(self):
        """The plan's 3.3 and the contract's behind_hours: the third run of a release that did not end done, and 6 hours
        behind the newest release after such a run, each ask for an early report once, so that a fleet that stops
        taking releases is seen within hours and not after a day. The block's tries count those runs, and its cause
        is the last one's. A read of the version at HEAD that fails once (git's time, no memory for a process) asks
        no more: with no row that it runs, the floor would read "none" and then the version again, two asks. That
        holds also for the first read of a new process, which has no earlier reading to keep."""
        self.switch(True)
        t0 = hub.now()
        self.look(t0)                           # the first look: no release yet
        row = self.release("2026.11.710", "kept", step="fetch", cause="dns", finished=t0 + 10)
        self.assertIsNone(self.look(t0 + 60))
        with hub.LOCK:
            hub.q("UPDATE releases SET state='rolled_back', finished=? WHERE revision=?", (t0 + 70, row["revision"]))
        self.assertIsNone(self.look(t0 + 120))
        with hub.LOCK:
            hub.q("UPDATE releases SET state='failed', cause='timeout', finished=? WHERE revision=?",
                  (t0 + 130, row["revision"]))
        self.assertIsNotNone(self.look(t0 + 180))
        self.assertIsNone(self.look(t0 + 240))      # once
        self.assertIsNotNone(self.look(t0 + 60 + errorreports.BEHIND_WAIT))
        with unittest.mock.patch.object(hub, "running_version", lambda: "unknown"):
            self.assertIsNone(self.look(t0 + 120 + errorreports.BEHIND_WAIT))
        self.assertIsNone(self.look(t0 + 180 + errorreports.BEHIND_WAIT))
        hub._error_report["head"] = None        # a new process, whose first read fails: no reading to keep
        with unittest.mock.patch.object(hub, "running_version", lambda: "unknown"):
            self.assertIsNone(self.look(t0 + 240 + errorreports.BEHIND_WAIT))
        self.assertIsNone(self.look(t0 + 300 + errorreports.BEHIND_WAIT))
        release = self.health()["release"]
        self.assertEqual((release["newest"], release["state"], release["tries"], release["cause"], release["since"]),
                         ("2026.11.710", "failed", 3, "timeout", round(t0 + 60, 3)))

    def test_six_hours_behind_ask_once_for_each_time_behind(self):
        """The 6-hour early report goes once for each time behind: new releases that come while the hub stays behind,
        and a release behind that leaves the rows that the look reads, ask no second one; the end of that time behind,
        when the hub runs the newest release, asks once more, because our side reads a hub's newest report and would
        count it as behind until its next day's report; a new time behind asks again."""
        self.switch(True)
        t0 = hub.now()
        self.release("2026.11.700", "done", finished=t0 - 100)
        self.look(t0)
        self.release("2026.11.701", "kept", step="fetch", cause="dns", finished=t0 + 10)
        self.look(t0 + 60)
        self.assertIsNotNone(self.look(t0 + 60 + errorreports.BEHIND_WAIT))
        with unittest.mock.patch.object(hub, "RELEASE_WALK", 1):        # the look reads the 4 newest rows
            for n in range(2, 7):
                self.release(f"2026.11.70{n}", "verified")
                self.assertIsNone(self.look(t0 + 120 * n + errorreports.BEHIND_WAIT), n)
        newest = self.release("2026.11.707", "done", finished=t0 + 2000)
        self.assertIsNotNone(self.look(t0 + 2000 + errorreports.BEHIND_WAIT))     # the hub runs the newest: once
        self.assertIsNone(self.look(t0 + 2100 + errorreports.BEHIND_WAIT))
        self.release("2026.11.708", "kept", step="fetch", cause="dns", finished=t0 + 3000)
        self.look(t0 + 3000)
        self.assertIsNotNone(self.look(t0 + 3000 + 2 * errorreports.BEHIND_WAIT), newest["version"])

    def test_a_run_that_the_fleet_holds_on_purpose_asks_for_no_early_report(self):
        """A fleet on a branch of its own, or with changes of its own, ends each release kept at that cause, and our
        side counts no fleet behind for those causes (fleet-health.ts). Its third run and its 6 hours behind ask for
        no early report, which would only use the day's four; the runs still count."""
        self.switch(True)
        t0 = hub.now()
        self.look(t0)
        row = self.release("2026.11.710", "kept", step="branch", cause="branch", finished=t0 + 10)
        self.look(t0 + 60)
        for t in (t0 + 70, t0 + 130):
            with hub.LOCK:
                hub.q("UPDATE releases SET finished=? WHERE revision=?", (t, row["revision"]))
            self.assertIsNone(self.look(t + 50))
        self.assertIsNone(self.look(t0 + 60 + errorreports.BEHIND_WAIT))
        self.assertEqual(self.health()["release"]["tries"], 3)

    def test_a_newer_release_does_not_start_the_time_behind_again(self):
        """`since` is when the hub first learned of a release newer than the one that it runs, `tries` its runs that did
        not end done since then, and `cause` the last one's, so a fleet that stays behind while new releases come is
        behind for that whole time, and not again from zero at each release, where our side would never see it 6
        hours behind. When it runs the newest release, the time behind ends."""
        self.switch(True)
        t0 = hub.now()
        self.release("2026.11.700", "done", finished=t0 - 100)
        self.look(t0)
        self.release("2026.11.701", "kept", step="fetch", cause="dns", finished=t0 + 50)
        self.look(t0 + 60)
        two = self.release("2026.11.702", "kept", step="fetch", cause="timeout", finished=t0 + 110)
        self.look(t0 + 120)
        release = self.health()["release"]
        self.assertEqual({k: release[k] for k in ("newest", "since", "tries", "cause", "behind")},
                         {"newest": "2026.11.702", "since": round(t0 + 60, 3), "tries": 2, "cause": "timeout",
                          "behind": 2})
        self.assertIsNotNone(self.look(t0 + 60 + errorreports.BEHIND_WAIT))     # 6 hours from the first one
        with hub.LOCK:
            hub.q("UPDATE releases SET state='done', step='follow', cause=NULL WHERE revision=?", (two["revision"],))
        release = self.health()["release"]
        self.assertEqual({k: release[k] for k in ("state", "since", "tries", "cause", "behind")},
                         {"state": "done", "since": None, "tries": 0, "cause": "none", "behind": 0})

    def test_a_release_that_the_channel_holds_starts_no_time_behind(self):
        """A release that our side holds (its row `held`) cannot fail a run here, so it starts no time behind: its time
        starts when the hub sees it no longer held. Else, after a hold of 6 hours, the first run of it that did not end
        done would count each fleet as 6 hours behind at once. And when the hub runs a newer release than at its
        6-hour report while a held one stays behind, that time behind ends with one more early report too: our side
        would else count the fleet as behind until its next day's report."""
        self.switch(True)
        t0, hour = hub.now(), 3600
        self.release("2026.11.700", "done", finished=t0 - 100)
        self.look(t0)
        one = self.release("2026.11.710", "held")
        self.assertIsNone(self.look(t0 + 60))
        with hub.LOCK:
            hub.q("UPDATE releases SET state='verified' WHERE revision=?", (one["revision"],))
        self.assertIsNone(self.look(t0 + 8 * hour))         # our side ends the hold
        with hub.LOCK:
            hub.q("UPDATE releases SET state='kept', step='hold', cause='busy', finished=? WHERE revision=?",
                  (t0 + 8 * hour + 60, one["revision"]))
        self.assertIsNone(self.look(t0 + 8 * hour + 120))
        release = self.health()["release"]
        self.assertEqual((release["since"], release["tries"], release["behind"]), (round(t0 + 8 * hour, 3), 1, 1))
        self.assertIsNotNone(self.look(t0 + 8 * hour + errorreports.BEHIND_WAIT))
        self.release("2026.11.720", "held")
        self.assertIsNone(self.look(t0 + 15 * hour))
        with hub.LOCK:
            hub.q("UPDATE releases SET state='done', step='follow', cause=NULL WHERE revision=?", (one["revision"],))
        self.assertIsNotNone(self.look(t0 + 16 * hour))     # it runs 2026.11.710, and only the held one is behind
        self.assertIsNone(self.look(t0 + 17 * hour))
        release = self.health()["release"]
        self.assertEqual((release["state"], release["behind"], release["tries"]), ("held", 1, 0))

    def test_a_release_that_is_there_when_reports_start_has_its_time_behind(self):
        """A release that the hub does not run and that is there at the first look gets the first time that its row
        holds (its run's start), else the time of that look: a time later than the true one, so the wait reads
        shorter and never longer. With no time our side would never count that fleet as behind."""
        t0 = hub.now()
        self.release("2026.11.700", "done", finished=t0 - 9000)
        self.release("2026.11.710", "kept", step="fetch", cause="dns", started=t0 - 7200, finished=t0 - 7100)
        self.switch(True)
        release = self.health()["release"]
        self.assertEqual((release["since"], release["tries"], release["cause"]), (round(t0 - 7200, 3), 1, "dns"))

    def test_the_newest_release_is_by_its_version_and_the_one_the_hub_restarts_onto_counts_as_run(self):
        """`newest` is the newest version that the channel named, not the newest row (a fleet that changed its track
        records an older release after a newer one); `behind` counts the releases newer than the one that runs that it
        did not take, and a release kept at `already` is one that it runs; and the report just before the restart
        onto a release names the release of the code that runs now and counts the new one as run (state done, not
        behind): else the faults of the old code would be kept under the new release, and a hub about to be in order
        would read as stuck for a day."""
        self.switch(True)
        t0 = hub.now()
        self.release("2026.11.700", "done", finished=t0 - 100)
        self.look(t0 - 50)
        newest = self.release("2026.11.710", "verified")
        self.look(t0)
        self.release("2026.11.703", "kept", step="already", finished=t0)
        self.release("2026.11.705", "kept", step="fetch", cause="dns", finished=t0 + 1)
        with hub.LOCK:
            hub.kv_set("releases_status", 200)
        self.assertEqual(self.health()["release"], {"newest": "2026.11.710", "state": "verified", "step": None,
                                                    "cause": "dns", "tries": 1, "since": round(t0, 3), "behind": 2,
                                                    "channel": 200})
        versions = {"c" * 40: "2026.11.700", "HEAD": "2026.11.710", "d" * 40: "2026.11.710"}

        def git(*args, **how):              # the checkout's HEAD is at the new release already
            if args[:2] == ("cat-file", "blob"):
                return 0, json.dumps({"revision": "0" * 40, "version": versions[args[2].split(":")[0]]}), ""
            return 128, "", "fatal"

        # an error in the hub during the run leaves its row failed (settle_releases), and the restart goes to it
        for state, step in (("failed", "merge"), ("done", "follow")):
            with hub.LOCK:
                hub.q("UPDATE releases SET state=?, step=?, reached=? WHERE revision=?",
                      (state, step, "d" * 40, newest["revision"]))
            self.fault(canary())
            with unittest.mock.patch.object(hub, "git_kit", git), \
                    unittest.mock.patch.object(hub, "running_version", lambda: hub.version_at("HEAD")):
                body = hub.error_report_before_restart("c" * 40, "d" * 40)
            self.assertEqual(self.sent[-1][1], body)
            self.assertEqual(body["version"], "2026.11.700")
            self.assertEqual({k: body["health"]["release"][k] for k in ("newest", "state", "tries", "since", "behind")},
                             {"newest": "2026.11.710", "state": state, "tries": 0, "since": None, "behind": 0})
        self.assertEqual(hub.kv_json("error_reports_restart", dict)["to"], "d" * 40)

    def test_the_report_before_a_restart_goes_only_with_a_fault_of_the_code_that_runs(self):
        """The report before a restart onto new code is for the faults (exceptions and stalls) of the code that the
        restart replaces, and it is one of the day's four early reports. With no fault, also with refused calls
        alone, it waits for its day, as the privacy page says ("about once a day"), and so it does when four early
        reports went: a fleet that takes releases by itself would else send a report at each release. The restart's
        revision is kept all the same."""
        self.switch(True)
        self.sweep(hub.now())       # the day's report
        self.refusal()
        with hub.LOCK:
            self.assertEqual(len(hub.error_report_body(hub.kv_time("error_reports_sent"))["refusals"]), 1)
        self.assertIsNone(hub.error_report_before_restart("c" * 40, "d" * 40))
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(hub.kv_json("error_reports_restart", dict)["to"], "d" * 40)
        self.fault(canary())
        self.assertIsNotNone(hub.error_report_before_restart("c" * 40, "d" * 40))
        self.assertEqual((len(self.sent), len(hub.error_report_earlies())), (2, 1))
        with hub.LOCK:
            for _ in range(errorreports.EARLY_MOST - 1):
                hub.error_report_earlies(add=hub.now())
        self.fault(canary())
        self.assertIsNone(hub.error_report_before_restart("c" * 40, "d" * 40))
        self.assertEqual(len(self.sent), 2)

    def test_the_restart_waits_for_the_report_before_it_only_so_long(self):
        """The restart onto new code waits RESTART_REPORT_WAIT for the report before it, whatever the network does: a
        send that hangs (packets that are dropped, a resolver that does not answer) goes on in its thread, and the
        new code is not held back while the release's row says done."""
        self.switch(True)
        self.fault(canary())
        go = threading.Event()
        self.addCleanup(go.set)

        def slow(url, body, timeout=None):
            go.wait(4)
            self.sent.append((url, body))

        with unittest.mock.patch.object(hub, "RESTART_REPORT_WAIT", 0.2), \
                unittest.mock.patch.object(errorreports, "send", slow):
            began = time.monotonic()
            body = hub.error_report_before_restart("c" * 40, "d" * 40)
            waited = time.monotonic() - began
            go.set()
            hub._error_report["thread"].join(10)
        self.assertIsNotNone(body)
        self.assertLess(waited, 2)
        self.assertEqual(len(self.sent), 1)     # it went in its thread

    def test_nothing_is_kept_or_sent_for_a_restart_or_a_start_while_reports_are_off(self):
        """The owner's switch: with error reports off, a restart onto new code keeps no mark and sends no report, a
        restart whose command failed asks for no early report, and a start counts in no report and asks for none, also
        after a stop that the hub did not plan."""
        self.fault(canary())
        self.assertIsNone(hub.error_report_before_restart("c" * 40, "d" * 40))
        with hub.LOCK:
            hub.error_report_runs_old("c" * 40)
        with hub.LOCK:
            hub.kv_set("error_reports_running", "1")
        hub.error_reports_started()
        self.assertEqual((hub.kv_get("error_reports_restart"), hub.kv_get("error_reports_starts"),
                          hub.kv_get("error_reports_early_at"), self.sent), (None, None, None, []))

    def test_a_report_during_a_restart_onto_new_code_names_the_code_that_runs(self):
        """From the start of a restart onto new code until the process ends (the compile in pieces, the report before
        it, a bridge's restart, the drain: up to some minutes), the checkout's HEAD is at the new release while this
        process runs the code before it. A report that the tick sends then names the release of that code, whose code
        id and faults it holds: else our side would keep the old code's faults under the new release."""
        self.switch(True)
        t0 = hub.now()
        self.sweep(t0)                          # the day's report
        with unittest.mock.patch.object(hub, "same_code", lambda a, b: False), \
                unittest.mock.patch.object(hub, "RESTART_DELAY", 0), \
                unittest.mock.patch.object(hub, "error_report_before_restart", lambda *revs: None), \
                unittest.mock.patch.dict(hub.CFG, hub_restart=["true"]), \
                unittest.mock.patch.object(hub, "running_version", lambda: hub.version_at("HEAD")), \
                self.git({"c" * 40: "2026.11.700", "HEAD": "2026.11.710"}):
            hub.restart_hub_soon("c" * 40, "d" * 40)     # its command ended well, and this process has not ended yet
            for thread in threading.enumerate():
                if thread.name == "release-restart":
                    thread.join(10)
            with hub.LOCK:
                hub.error_report_early("a test")
            self.sweep(t0 + 60)
        self.assertEqual([body["version"] for _, body in self.sent[1:]], ["2026.11.700"])

    def test_a_restart_sends_the_report_first_and_one_that_fails_asks_for_an_early_one(self):
        """restart_hub_soon gives the report before the restart its two revisions before the new code runs, and a
        restart command that fails, which leaves the hub on its old code, asks for an early report and ends the
        restart's mark (that failure is said: a later start by hand onto the new code is no start on old code). That
        report, and each one after it from this process, names the release of the code that still runs while the
        checkout's HEAD is at the new release, and its block counts the new release as behind, with the failed
        restart as a try of cause "other": else the faults of the old code would be kept under the new release, and
        our side would read a hub that runs its newest release. A restore's restart that fails goes onto no new code,
        and asks for none."""
        t0 = hub.now()
        self.release("2026.11.700", "done", finished=t0 - 9000)
        new = self.release("2026.11.710", "done", step="follow", started=t0 - 200, finished=t0 - 100, reached="d" * 40)
        self.switch(True)
        self.sweep(t0)                          # the day's report, and the first look
        with hub.LOCK:
            hub.kv_set("error_reports_restart", json.dumps({"to": "d" * 40, "at": t0}))
        calls = []
        with unittest.mock.patch.object(hub, "same_code", lambda a, b: False), \
                unittest.mock.patch.object(hub, "RESTART_DELAY", 0), \
                unittest.mock.patch.object(hub, "error_report_before_restart", lambda *revs: calls.append(revs)), \
                unittest.mock.patch.dict(hub.CFG, hub_restart=["false"]), contextlib.redirect_stdout(io.StringIO()), \
                self.git({"c" * 40: "2026.11.700", "HEAD": "2026.11.710"}):
            for revs, always in (((None, None), True), (("c" * 40, "d" * 40), False)):
                hub.restart_hub_soon(*revs, always=always)
                for thread in threading.enumerate():
                    if thread.name == "release-restart":
                        thread.join(10)
                if always:
                    self.assertIsNone(hub.kv_time("error_reports_early_at"))
        self.assertEqual(calls, [("c" * 40, "d" * 40)])
        self.assertIsNotNone(hub.kv_time("error_reports_early_at"))
        self.assertIsNone(hub.kv_get("error_reports_restart"))
        with self.git({"c" * 40: "2026.11.700", "HEAD": "2026.11.710"}), \
                unittest.mock.patch.object(hub, "running_version", lambda: hub.version_at("HEAD")):
            self.sweep(t0 + 60)
        ((_, body),) = self.sent[1:]
        self.assertEqual(body["version"], "2026.11.700")
        self.assertEqual(body["health"]["release"], {"newest": "2026.11.710", "state": "failed", "step": "follow",
                                                     "cause": "other", "tries": 1, "since": round(t0 - 200, 3),
                                                     "behind": 1, "channel": 0})
        self.assertEqual(new["version"], body["health"]["release"]["newest"])
        # A second release, and a restart onto it from this same old code: that report counts the release that it
        # restarts onto, and each one under it, as run, so that a hub about to run its newest release does not read
        # as stuck for a day.
        self.release("2026.11.720", "done", step="follow", started=t0 + 70, finished=t0 + 80, reached="e" * 40)
        self.fault(canary())
        with self.git({"c" * 40: "2026.11.700", "HEAD": "2026.11.720", "e" * 40: "2026.11.720"}):
            again = hub.error_report_before_restart("d" * 40, "e" * 40)
        self.assertEqual(again["version"], "2026.11.700")
        self.assertEqual(again["health"]["release"], {"newest": "2026.11.720", "state": "done", "step": "follow",
                                                      "cause": "none", "tries": 0, "since": None, "behind": 0,
                                                      "channel": 0})

    def test_a_fleet_with_no_restart_command_reports_the_code_that_runs(self):
        """With no restart command (CFG hub_restart []), the hub goes on with its old code after a release: its reports
        name that code's release, and the new one is behind, also when the owner turns error reports on after that
        release (the code that runs is a fact of the process, and no record). Such a fleet chose it: no try counts and
        no early report goes, now or 6 hours later."""
        t0 = hub.now()
        self.release("2026.11.700", "done", finished=t0 - 9000)
        self.release("2026.11.710", "done", step="follow", started=t0 - 200, finished=t0 - 100, reached="d" * 40)
        with unittest.mock.patch.object(hub, "same_code", lambda a, b: False), \
                unittest.mock.patch.dict(hub.CFG, hub_restart=[]), \
                self.git({"c" * 40: "2026.11.700", "HEAD": "2026.11.710"}):
            self.assertIsNone(hub.restart_hub_soon("c" * 40, "d" * 40))
            self.switch(True)
            with unittest.mock.patch.object(hub, "running_version", lambda: hub.version_at("HEAD")):
                self.sweep(t0)
                self.assertIsNone(self.look(t0 + 2 * errorreports.BEHIND_WAIT))
        ((_, body),) = self.sent
        release = body["health"]["release"]
        self.assertEqual((body["version"], release["state"], release["behind"], release["tries"], release["cause"]),
                         ("2026.11.700", "done", 1, 0, "none"))

    def test_each_check_of_the_server_watch_goes_once_and_says_whom_it_fails(self):
        """The checks are the server watch's facts, each code once and the passing ones too: `hub` true while the hub's
        own server fails it, false while the watch can say that it does not, null else; `servers` the other servers
        that fail it; `since` the earliest look that saw one of them fail, null when one failed before the first look.
        A hub that counted its own server among the servers, or left the passing checks out, would read to our side
        as a fleet that is wrong, or as one that reads nothing."""
        self.watch({"web-1": {"told": ["disk"]}})
        self.switch(True)
        t0 = hub.now()
        self.look(t0)
        self.watch({"hub": {"told": ["memory"]}, "web-1": {"told": ["disk"]}, "web-2": {"told": ["disk", "memory"]}})
        self.look(t0 + 60)
        checks = self.health()["checks"]
        self.assertEqual(sorted(c["code"] for c in checks),
                         sorted(list(hub.WATCH_WORDS) + list(dict.fromkeys(hub.WARNING_CODES.values()))))
        found = {c["code"]: (c["hub"], c["servers"], c["since"]) for c in checks}
        self.assertEqual((found["memory"], found["disk"], found["firewall"], found["macos_update"]),
                         ((True, 1, round(t0 + 60, 3)), (False, 2, None), (None, 0, None), (False, 0, None)))

    def test_a_warning_whose_way_out_is_ours_goes_as_its_code_and_asks_once(self):
        """F5 piece 3: a warning of the owner's System status whose way out is ours ("Tell us", Report a problem) goes
        in the report by itself while the switch is on, as its code, with the hub's own server, the count of the
        others and since when; and nothing goes while the switch is off. A code that turns bad asks for one early
        report, and the same code at the next look for none; a new event of it asks again. A silent helper asks for
        none: a Mac that sleeps silences its own. A new yes of the owner starts the record again: its first look asks
        for nothing, because the day's report goes then. Believable bugs: a warning that never reaches our side; one
        warning that sends four early reports a day; a report at each sleep of a Mac; a yes that spends one of the
        day's four early reports on what its day's report carries."""
        t0 = hub.now()
        with hub.LOCK:          # the manager's helper answers: no helper is silent before web-agent's
            hub.q("INSERT OR REPLACE INTO agents(name, last_seen) VALUES('manager', ?)", (t0,))
            hub.q("INSERT OR REPLACE INTO machine_status(agent, data, reported) VALUES('manager', '{}', ?)", (t0,))
            hub.kv_set("integrity", "a test")
        self.sweep(t0)
        self.assertEqual(self.sent, [])         # off: nothing, and no record either
        self.assertIsNone(hub.kv_get("error_reports_warnings"))
        with hub.LOCK:
            hub.kv_set("integrity", "ok")
        self.switch(True)
        self.sweep(t0)                          # the day's report, and the first look
        self.assertEqual(len(self.sent), 1)
        with hub.LOCK:
            hub.kv_set("integrity", "a test")
        self.assertIsNotNone(self.look(t0 + 60))
        self.assertIsNone(self.look(t0 + 120))  # it stands still: no second ask
        hub.TEAM["agents"]["web-agent"] = {"role": "worker", "runtime": "claude", "machine": "web-1", "can": []}
        self.assertIsNone(self.look(t0 + 180))  # a helper that goes silent asks for none
        found = {c["code"]: (c["hub"], c["servers"], c["since"]) for c in self.health()["checks"]}
        self.assertEqual((found["records"], found["helper"], found["timers"], found["release_start"]),
                         ((True, 0, round(t0 + 60, 3)), (False, 1, round(t0 + 180, 3)), (False, 0, None),
                          (False, 0, None)))
        with hub.LOCK:
            hub.kv_set("integrity", "ok")
        self.assertIsNone(self.look(t0 + 240))
        with hub.LOCK:
            hub.kv_set("integrity", "a test")       # a new event of the same code
            hub.kv_set("tick_ok", repr(hub.now() - 2 * hub.TICK_WARN))     # and the timers stop
        hub._error_report["looked"] = None      # the pass's own look, as a minute later
        self.sweep(t0 + 300)                    # one early report, with both codes
        self.sweep(t0 + 305)
        found = {c["code"]: c["hub"] for c in self.sent[-1][1]["health"]["checks"]}
        self.assertEqual((len(self.sent), found["records"], found["timers"]), (2, True, True))
        self.switch(False)
        with hub.LOCK:
            hub.kv_set("schema_problems", json.dumps(["a step"]))
        self.switch(True)
        self.assertIsNone(self.look(t0 + 360))  # a new yes: a first look again

    def test_a_failed_first_read_of_the_version_holds_the_six_hour_report_back_for_minutes_only(self):
        """The second read of F5 piece 3, N1: a new process whose first read of the version at HEAD fails (git's time,
        no memory for a new process) has no earlier reading to keep. Its looks say nothing of a time behind while the
        version is not known, and the version is read again some minutes later, also while HEAD stays, so the 6-hour
        report comes when its time comes. A reading of "unknown" kept by HEAD would turn that report off until a
        delivery moved HEAD, which can be days on a quiet fleet, on the fleet with no row that it runs that most needs
        it."""
        self.switch(True)
        t0 = hub.now()
        with unittest.mock.patch.object(hub, "kit_revision", lambda fresh=False: "a" * 40):     # HEAD stays
            self.look(t0)                       # the first look: no release yet
            self.release("2026.11.710", "kept", step="fetch", cause="dns", finished=t0 + 10)
            self.assertIsNone(self.look(t0 + 60))
            hub._error_report["head"] = None    # a new process, whose first read fails
            with unittest.mock.patch.object(hub, "running_version", lambda: "unknown"):
                self.assertIsNone(self.look(t0 + 120))
            self.assertIsNone(self.look(t0 + 180))      # "unknown" for some minutes more, then read again
            self.assertIsNotNone(self.look(t0 + 60 + errorreports.BEHIND_WAIT))
            self.assertIsNone(self.look(t0 + 120 + errorreports.BEHIND_WAIT))      # once

    def test_the_looks_keep_since_and_tries_while_our_side_holds_the_block(self):
        """The second read of F5 piece 3, round 2 (R2-1): for the DAY after our side refused the health block, the block
        does not go, but the looks go on. They alone write the records of `since` and `tries`, because a release's row
        keeps only its last run. So a release that comes in the hold and fails three times in it has, in the first
        block after the hold, `since` at the look that first saw it and 3 tries. A hold with no look would count the
        runs of that day as one try, with a `since` up to a day late, at every fleet at once: a hold comes from a 400
        to the block, so from a release of the hub that the site does not take yet. The cost that W15 accepted stays:
        an early report asked in the hold goes with no block."""
        self.switch(True)
        t0 = hub.now()
        self.sweep(t0)                          # the day's report, and the first look
        with hub.LOCK:
            hub.kv_set("error_reports_health_hold", repr(t0 + errorreports.DAY))
        row = self.release("2026.11.710", "kept", step="fetch", cause="dns", finished=t0 + 3600)
        self.look(t0 + 3660)
        asked = None
        for n, state in ((2, "rolled_back"), (3, "failed")):
            with hub.LOCK:
                hub.q("UPDATE releases SET state=?, cause='timeout', finished=? WHERE revision=?",
                      (state, t0 + n * 3600, row["revision"]))
            asked = self.look(t0 + n * 3600 + 60)
        with hub.LOCK:
            hub.kv_set("error_reports_health_hold", None)       # the day ended
        release = self.health()["release"]
        self.assertEqual((release["tries"], release["since"], release["cause"]), (3, round(t0 + 3660, 3), "timeout"))
        self.assertIsNotNone(asked)             # the third run that did not end done asked, also in the hold

    def test_a_new_yes_during_a_send_keeps_the_counts_of_that_yes(self):
        """The second read of F5 piece 3, N7 (W15): the owner turns error reports off and on while a report with the
        block is on its way. His new yes starts the block's counts again (error_reports_counts_start), and the send
        that our side then takes does not write back the counts of its body, made before that yes: the next block
        would count kills for want of memory from before his yes."""
        self.switch(True)                       # 3 kills at his yes

        def site(url, body, timeout=None):
            self.sent.append((url, body))
            self.machine(kills=7)               # 4 more during the send, before his new yes
            with hub.LOCK:
                hub.set_error_reports(False)
                hub.set_error_reports(True)

        with unittest.mock.patch.object(errorreports, "send", site):
            self.sweep(hub.now())
        self.assertEqual((len(self.sent), "health" in self.sent[0][1]), (1, True))
        self.assertEqual(self.health()["machine"]["ooms"], 0)

    def test_a_servers_update_that_failed_or_is_behind_goes_as_its_code_and_asks_nothing(self):
        """The owner's answer to card F5-3 (22 November 2026): "Send it, and add the clause: a server's update failed or
        is behind". machine_failed and machine_behind go as the code server_update: `hub` for the hub's own server,
        `servers` for each other server once, whatever the number of its agents, and `since`. It asks for no early
        report: the owner's own button (Update <Agent>) settles it, and an update that waits for its turn, is asked
        or runs is no warning, so it is not counted. Believable bugs: a failed update never reaches our side; the
        hub's own server counted among the others, or a server once for each agent; each update that fails spends one
        of the day's four."""
        self.switch(True)
        t0 = hub.now()
        self.sweep(t0)                          # the day's report, and the first look
        for name, server in (("web-agent", "web-1"), ("web-second", "web-1"), ("db-agent", "db-1")):
            hub.TEAM["agents"][name] = {"role": "worker", "runtime": "claude", "machine": server, "can": []}
        with hub.LOCK:
            for name in hub.TEAM["agents"]:     # each helper answers, and each status is new: no `helper`
                hub.q("INSERT OR REPLACE INTO agents(name, last_seen) VALUES(?, ?)", (name, t0))
                hub.q("INSERT OR REPLACE INTO machine_status(agent, data, reported) VALUES(?, ?, ?)",
                      (name, json.dumps({"revision": "b" * 40 if name == "db-agent" else "a" * 40}), t0))
            for name in ("manager", "web-agent", "web-second"):     # the hub's own server, and web-1 twice
                hub.q("INSERT OR REPLACE INTO machine_updates(agent, state, requested) VALUES(?, 'failed', ?)",
                      (name, t0))
        with unittest.mock.patch.object(hub, "kit_revision", lambda fresh=False: "a" * 40), \
                unittest.mock.patch.object(hub, "same_code", lambda a, b: a == b):    # db-1 runs older code
            self.assertIsNone(self.look(t0 + 60))
            found = {c["code"]: (c["hub"], c["servers"], c["since"]) for c in self.health()["checks"]}
        self.assertEqual((found["server_update"], found["helper"]), ((True, 2, round(t0 + 60, 3)), (False, 0, None)))

    def test_a_hub_with_no_proc_sends_its_report_without_the_block(self):
        """A hub on a Mac has no /proc: its report goes as before, with no block, because every key of the block is
        required and a memory or a count of kills made up there would be a false word. A check that turns bad on its
        own server asks for no early report either: that report would hold nothing of it, and use one of the day's
        four."""
        os.remove(os.path.join(self.proc, "vmstat"))
        self.switch(True)
        t0 = hub.now()
        self.sweep(t0)
        ((_, body),) = self.sent
        self.assertNotIn("health", body)
        self.watch({"hub": {"told": ["memory"]}})
        self.assertIsNone(self.look(t0 + 60))


class StartAndStop(unittest.TestCase):
    """A real hub process, as its service starts and stops it (main and after_serving)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="fleet-error-starts-"))
        self.addCleanup(shutil.rmtree, str(self.root), ignore_errors=True)
        (self.root / "team.json").write_text(json.dumps({
            "hub": {"machine": "hub", "port": 8765}, "addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2"},
            "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []}}}))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]

    def kv(self, key):
        try:
            with contextlib.closing(sqlite3.connect(f"file:{self.root / 'hub.db'}?mode=ro", uri=True)) as db:
                row = db.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
        except sqlite3.Error:
            return None
        return row[0] if row else None

    def start(self):
        """A hub of these records, whose first pass of the tick is 10 minutes away: it sends nothing. It is up once its
        start line is out (error_reports_started runs before it) and its mark says that it runs (after its handler of
        SIGTERM): a hub that was killed left the mark of its own."""
        self.starts = getattr(self, "starts", 0) + 1
        pipe, fds = parent_pipe(self.root)
        with open(self.root / "out.txt", "a") as out:
            proc = subprocess.Popen([sys.executable, "-m", "hub", "--host", "127.0.0.1", "--port", str(self.port),
                                     "--db", str(self.root / "hub.db"), "--team", str(self.root / "team.json"),
                                     "--tick", "600", "--parent-pipe", str(pipe)],
                                    pass_fds=fds, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    cwd=ROOT, env=dict(os.environ, HOME=str(self.root)))
        self.addCleanup(lambda: proc.poll() is None and (proc.kill(), proc.wait()))
        deadline = time.monotonic() + 90     # as test_hub_keeps_port gives a start on this Mac
        while (self.root / "out.txt").read_text().count("Founderizer hub on") < self.starts or \
                self.kv("error_reports_running") != "1":
            self.assertIsNone(proc.poll(), (self.root / "out.txt").read_text())
            self.assertLess(time.monotonic(), deadline, (self.root / "out.txt").read_text())
            time.sleep(0.1)
        return proc

    def test_a_hub_marks_that_it_runs_and_the_stop_of_its_service_clears_the_mark(self):
        """main() counts each start and sets the mark that the hub runs, and the stop of its service (SIGTERM,
        after_serving) clears the mark, so the start after a crash (SIGKILL, a kill for lack of memory) is the one
        that asks for an early report. Without the calls in main the starts would stay 0 and a crash would read as
        planned; without the one in after_serving each restart would send an early report."""
        proc = self.start()
        proc.terminate()
        proc.wait(30)
        self.assertIsNone(self.kv("error_reports_running"))
        with contextlib.closing(sqlite3.connect(self.root / "hub.db")) as db, db:
            db.executemany("INSERT OR REPLACE INTO kv(k, v) VALUES(?, ?)",
                           [("error_reports", "1"), ("release_channel", "https://example.invalid")])
        proc = self.start()
        self.assertEqual((self.kv("error_reports_starts"), self.kv("error_reports_early_at")), ("1", None))
        proc.kill()                             # a stop that the hub did not plan
        proc.wait(30)
        proc = self.start()
        self.assertEqual(self.kv("error_reports_starts"), "2")
        self.assertIsNotNone(self.kv("error_reports_early_at"))
        proc.terminate()
        proc.wait(30)

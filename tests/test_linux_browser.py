"""The agents' browser on a Linux server, the helper's side (build plan 04, S2): its unit and its start, the DevTools
MCP server that a browser task's session gets, the closes and starts at waits, the clear of a login whose grant
ended, and `Helper.sweep_browser` (S2a), which stops an agent's browser and screen-sharing units where no open task
holds them. The live checks of 17 November 2026 on a throwaway x86 Ubuntu 24.04 server ran the real Claude Code
2.1.311 and Codex 0.169.0 through all of it; these tests keep what those checks found."""
import contextlib
import io
import json
import os
import re
import shlex
import socket
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import fleet
import hub
import lifecycle
from leftovers import scratch_home

STOPS = [["systemctl", "--user", "--no-block", "stop", "fleet_browser.service"],
         ["systemctl", "--user", "--no-block", "stop", "fleet_vnc.service"]]


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)
    os.makedirs(fleet.HOME, exist_ok=True)      # a helper's own folder is always there: its files are written in it


class SweepBrowser(unittest.TestCase):
    """S2a: a helper that started again, a task that ended while the helper did not run or under a release that took
    the browser back leaves no Chrome running for long; a browser that an open task holds stays."""

    def sweep(self, open_tasks, windows=(), worker=True, at=None, platform="linux", own=True, answer=0, now=5000.0,
              can=("shell", "browser"), gone=None, state=("inactive", "inactive")):
        """One call on a stand-in helper. `windows` are tmux's lines "<name>\\t<needs>", given only to the right
        list-windows; None is a tmux that does not answer, "gone" a session that is not there. `answer` is systemd's
        exit code for each stop, and `state` what its is-active says of each unit. Returns (the stops asked for, when
        the helper counts its last sweep)."""
        helper = types.SimpleNamespace(open_tasks=open_tasks, worker=worker, browser_at=at, session="fleet-ivy",
                                       own_user=lambda: own, conf={"can": list(can)},
                                       browser_data_gone=lambda: (gone if gone is not None else []).append(1))

        def tmux(*args):
            if args != ("list-windows", "-t", "=fleet-ivy:", "-F", "#{window_name}\t#{@fleet_needs}"):
                return subprocess.CompletedProcess(args, 0, "T-1\tnone\n", "")      # another list: not this one
            if windows is None:
                return subprocess.CompletedProcess(args, 1, "", "server exited unexpectedly")
            if windows == "gone":
                return subprocess.CompletedProcess(args, 1, "", "can't find session: fleet-ivy")
            return subprocess.CompletedProcess(args, 0, "".join(w + "\n" for w in windows), "")
        stops = []

        def run(argv, **_):
            if argv[:3] == ["systemctl", "--user", "is-active"]:
                said = dict(zip(fleet.lifecycle.BROWSER_UNITS, state))[argv[3]]
                return subprocess.CompletedProcess(argv, 0 if said == "active" else 3, said + "\n", "")
            stops.append(argv)
            return subprocess.CompletedProcess(argv, answer, "", "Failed to connect to bus")
        with patch.object(fleet, "tmux", tmux), patch.object(fleet.sys, "platform", platform), \
                patch.object(fleet.time, "monotonic", lambda: now), contextlib.redirect_stdout(io.StringIO()):
            fleet.Helper.sweep_browser(helper, stop=run)
        return stops, helper.browser_at

    def test_the_units_that_no_open_task_holds_stop(self):
        # A browser task that is not open any more, a task of another kind, a manager (its hub names no open task),
        # no window, and a session that is not there at all.
        for open_tasks, windows, worker in ((["T-2"], ["T-1\tbrowser"], True), (["T-1"], ["T-1\tnone"], True),
                                            (None, ["T-1\tbrowser"], False), ([], [], True), (["T-1"], "gone", True)):
            self.assertEqual(self.sweep(open_tasks, windows, worker), (STOPS, 5000.0), (open_tasks, windows))

    def test_a_browser_that_an_open_task_holds_stays(self):
        self.assertEqual(self.sweep(["T-4", "T-1"], ["home\t", "T-1\tbrowser", "T-3\tnone"]), ([], 5000.0))
        # A window whose needs tmux did not take (its start ran out of time) may be a browser task's.
        self.assertEqual(self.sweep(["T-1"], ["T-1\t"]), ([], 5000.0))

    def test_a_stop_in_systemds_pause_after_a_crash_leaves_no_page_to_keep(self):
        """D5: systemd starts the unit again 2 s after a crash, and its own program deletes the session files then. A
        stop in that pause ends it first, and systemd then says that it ended well (measured on Ubuntu 24.04), so the
        sweep makes the name name nobody; a stop of a Chrome that runs leaves the name."""
        run = tempfile.mkdtemp(prefix="fleet-browser-run-")
        self.addCleanup(lambda: __import__("shutil").rmtree(run, True))
        pages = Path(run, "fleet-browser", "pages-task")
        pages.parent.mkdir()
        for state, wanted in (("activating", "\n"), ("active", f"{DB}\tT-1\tc-1\t1:1\n"),
                              ("", f"{DB}\tT-1\tc-1\t1:1\n")):          # a systemd that does not answer: it stays
            pages.write_text(f"{DB}\tT-1\tc-1\t1:1\n")
            with patch.dict(os.environ, {"XDG_RUNTIME_DIR": run}):
                self.assertEqual(self.sweep([], [], state=(state, "inactive"))[0], STOPS, state)
            self.assertEqual(pages.read_text(), wanted, state)

    def test_only_the_agents_own_os_user_has_these_units(self):
        """The units of a user's systemd are that user's: the helper of an agent that runs as the server's own user
        (an agent from before one OS user for each agent), or as another agent's, stops nothing."""
        helper = types.SimpleNamespace(agent="ivy", conf={"role": "worker"})
        for name, conf, own in (("fleet-ivy", {}, True), ("fleet", {}, False), ("fleet-kai", {}, False),
                                ("fleet-old", {"user": "fleet-old"}, True),
                                ("fleet-ivy", {"user": "fleet-old"}, False)):
            with patch.object(fleet.pwd, "getpwuid", lambda uid, name=name: types.SimpleNamespace(pw_name=name)):
                self.assertIs(fleet.Helper.own_user(types.SimpleNamespace(**dict(vars(helper), conf=conf))), own, name)

    def test_a_stop_that_keeps_failing_is_told_once(self):
        answer = lambda argv, **_: subprocess.CompletedProcess(argv, 1, "", "Failed to connect to bus")
        said = io.StringIO()
        with contextlib.redirect_stdout(said), patch.object(fleet, "BROWSER_TOLD", set()):
            self.assertFalse(fleet.stop_browser_units(answer))
            self.assertFalse(fleet.stop_browser_units(answer))
        self.assertEqual(said.getvalue().splitlines(), [f"the stop of {unit} failed (1): Failed to connect to bus"
                                                        for unit in fleet.lifecycle.BROWSER_UNITS])

    def test_at_each_start_and_then_every_ten_minutes(self):
        """A task that ended under a release that took the browser back, or while a stop was missed, leaves its
        Chrome for ten minutes at most; a stop that systemd did not take is tried again in a minute."""
        self.assertEqual(self.sweep(["T-1"], [], at=5000.0 - 599), ([], 5000.0 - 599))
        self.assertEqual(self.sweep(["T-1"], [], at=5000.0 - 600), (STOPS, 5000.0))
        stops, at = self.sweep(["T-1"], [], answer=1)
        self.assertEqual((stops, at), (STOPS, 5000.0 - fleet.PLACES_EVERY + 60))
        self.assertEqual(self.sweep(["T-1"], [], at=at, now=5059.0), ([], at))
        self.assertEqual(self.sweep(["T-1"], [], at=at, now=5060.0)[0], STOPS)

    def test_an_untick_takes_the_agents_own_browser_data_away_once_its_units_ended(self):
        """The owner, 18 November 2026: "Yes, delete them". An agent whose Browser box is off keeps no Chrome profile
        (its cookies and sign-ins), no browser tool and no browser unit, once no open task holds its units and systemd
        says that both have ended (Chrome writes its cookies as it ends); the fleet's Node stays, so does a package
        that an MCP server of the owner's names too, and so does every folder of the agent's own home: a project of its
        own called "browser" too. A stop that systemd did not take, an open browser task, and a Browser box that is on
        delete nothing; a unit that has not ended yet deletes nothing until the sweep a minute later."""
        for kwargs, deleted in ((dict(can=("shell",)), 1), (dict(can=("shell",), answer=1), 0),
                                (dict(can=("shell",), windows=["T-1\tbrowser"]), 0), ({}, 0),
                                (dict(can=("shell",), state=("failed", "inactive")), 1),
                                (dict(can=("shell",), state=("inactive", "deactivating")), 0),
                                (dict(can=("shell",), state=("active", "inactive")), 0)):
            gone = []
            self.sweep(["T-1"], gone=gone, **kwargs)
            self.assertEqual(len(gone), deleted, kwargs)
        self.assertEqual(self.sweep(["T-1"], can=("shell",), state=("deactivating", "inactive")),
                         (STOPS, 5000.0 - fleet.PLACES_EVERY + 60))
        h = helper(dict(CLAUDE, can=["shell"]))
        home = os.path.expanduser("~")
        made = [os.path.join(fleet.browser_profile(), "Default", "Cookies"),
                os.path.join(fleet.package_folder(fleet.BROWSER_MCP_PACKAGE), "ready.json"),
                os.path.join(fleet.programs_dir(), "node", "bin", "node"),
                os.path.join(home, ".config", "systemd", "user", "fleet_browser.service"),
                fleet.Helper.clears_file(h),
                os.path.join(home, "browser", "Default", "Cookies")]          # the agent's own project
        for path in made:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w").close()
        calls, call = systemd()
        owners = {"devtools": {"package": dict(fleet.BROWSER_MCP_PACKAGE), "tools": ["take_snapshot"]}}
        with patch.object(fleet, "systemctl_user", call), patch.object(fleet.lifecycle, "tool_catalog",
                                                                       lambda team: owners):
            fleet.Helper.browser_data_gone(h, team={"mcp": {}})     # the owner's own MCP server runs that package
        self.assertEqual((os.path.exists(made[0]), os.path.exists(made[1])), (False, True))
        h.said.clear()
        with patch.object(fleet, "systemctl_user", call):
            fleet.Helper.browser_data_gone(h, team={})
        self.assertEqual([os.path.exists(p) for p in made], [False, False, True, False, False, True])
        self.assertIn(("daemon-reload",), calls)
        self.assertEqual(h.said, ["its Browser box is off: its browser tool went from this server"])
        h.said.clear()
        fleet.Helper.browser_data_gone(h, team={})                   # nothing there: nothing said
        self.assertEqual(h.said, [])

    def test_nothing_is_decided_on_what_is_not_known(self):
        # Before the first poll, a worker's hub that names no open task, a tmux that does not answer, a Mac (whose
        # browser is the owner's Chrome), and an agent that shares its OS user with others.
        for kwargs in (dict(open_tasks=False), dict(open_tasks=None), dict(open_tasks=["T-1"], windows=None),
                       dict(open_tasks=["T-1"], platform="darwin"), dict(open_tasks=["T-1"], own=False)):
            self.assertEqual(self.sweep(**kwargs), ([], None), kwargs)



CLAUDE = {"role": "worker", "runtime": "claude", "can": ["shell", "browser"], "vault": "none",
          "start": lifecycle.RUNTIMES["claude"]["first_worker"],
          "allow": list(lifecycle.RUNTIMES["claude"]["full_access"]["allow"])}
CODEX = {"role": "worker", "runtime": "codex", "can": ["shell", "browser"], "vault": "none",
         "start": lifecycle.RUNTIMES["codex"]["first_worker"]}
WINDOWS = ("list-windows", "-t", "=fleet-ivy:", "-F", "#{window_name}\t#{@fleet_needs}")
DB = "0123456789ab"        # the hub's database generation of the stand-in helper's last poll
# systemd says that the agent's Chrome runs, and that no sharing of its screen does
ACTIVE = {"is-active": lambda args: (0, "active\n") if args[1] == "fleet_browser.service" else (3, "inactive\n")}


def systemd(answers=None):
    """A stand-in for systemctl_user: (its calls, the function). `answers` gives (code, output) by the call's first
    word; is-active says inactive unless it says otherwise."""
    calls, answers = [], dict({"is-active": (3, "inactive\n")}, **(answers or {}))

    def call(*args, timeout=30):
        calls.append(args)
        answer = answers.get(args[0], (0, ""))
        answer = answer(args) if callable(answer) else answer
        return answer[0], answer[1], answer[2] if len(answer) > 2 else ""
    return calls, call


def tmux_of(windows, attempt=""):
    """A stand-in for tmux: `windows` are the lines "<name>\t<needs>" of this agent's session; None does not answer.
    `attempt` is each window's @fleet_attempt ("<generation>:<attempt>")."""
    def tmux(*args):
        if args[:1] == ("show-options",) and args[-1] == "@fleet_attempt":
            return subprocess.CompletedProcess(args, 0, attempt + "\n" if attempt else "", "")
        if args != WINDOWS:
            return subprocess.CompletedProcess(args, 0, "", "")
        if windows is None:
            return subprocess.CompletedProcess(args, 1, "", "server exited unexpectedly")
        return subprocess.CompletedProcess(args, 0, "".join(w + "\n" for w in windows), "")
    return tmux


def helper(conf=CLAUDE, **fields):
    """A helper of the agent ivy with its own OS user, made as the live check made it, with no constructor."""
    h = fleet.Helper.__new__(fleet.Helper)
    h.agent, h.conf, h.session, h.worker, h.step, h.said = "ivy", dict(conf), "fleet-ivy", True, None, []
    h.browser_waiting, h.browser_retry, h.browser_told, h.open_tasks = set(), {}, {}, ["T-1"]
    h.browser_waits_seen, h.browser_fresh, h.poll_db = {}, set(), DB
    h.say = h.said.append
    h.own_user = lambda: True
    for name, value in fields.items():
        setattr(h, name, value)
    return h


class BrowserUnit(unittest.TestCase):
    """D5 and D12: the agent's browser unit, which only the helper writes and starts."""

    def test_the_unit_holds_one_place_restarts_twice_and_is_never_enabled(self):
        text = fleet.browser_unit_text("/usr/bin/python3", "/kit")
        for line in ("MemoryMax=1G", "MemorySwapMax=0", "OOMScoreAdjust=900", "Restart=on-failure",
                     "StartLimitBurst=3", "StartLimitIntervalSec=infinity",
                     "ExecStart=/usr/bin/python3 -E -s /kit/fleet.py browser-run",
                     "ExecStartPost=/usr/bin/python3 -E -s /kit/fleet.py browser-ready"):
            self.assertIn(line + "\n", text)
        self.assertNotIn("[Install]", text)         # no boot and no login start it: the helper alone
        self.assertNotIn("Environment=", text)

    def test_chrome_takes_the_owners_language_and_the_fleets_zone_and_nothing_else(self):
        """A new profile takes its languages from LANG (live: navigator.language "es-ES"), and the pages' times from
        TZ. Both come from team.json into the unit's own text, so a value with a new line would write a line of the
        unit: it gives none."""
        zones = tempfile.mkdtemp(prefix="fleet-zones-")
        self.addCleanup(lambda: __import__("shutil").rmtree(zones, True))
        for name in ("UTC", "Europe/Madrid"):
            Path(zones, name).parent.mkdir(parents=True, exist_ok=True)
            Path(zones, name).write_text("")

        def team(tag=None, zone=None):
            return {"settings": {"owner.language": tag} if tag else {}, "goals": {"timezone": zone} if zone else {}}
        hostile = team("es\nExecStart=/bin/sh", "Europe/Madrid\nExecStartPre=/bin/sh")
        for given, wanted in ((team("es-ES", "Europe/Madrid"), ("es_ES.UTF-8", "Europe/Madrid")),
                              (team("zh-Hans-CN"), ("zh_CN.UTF-8", "UTC")), (team("es-419"), ("es.UTF-8", "UTC")),
                              (team(), (None, "UTC")), (hostile, (None, None)),
                              (team("en-US", "../../etc/passwd"), ("en_US.UTF-8", None)),
                              (team("pt-BR", "America/Sao_Paulo"), ("pt_BR.UTF-8", None))):   # no such zone here
            self.assertEqual(fleet.browser_locale(given, zones=zones), wanted, given)
        text = fleet.browser_unit_text("/py", "/kit", locale=fleet.browser_locale(hostile, zones=zones))
        self.assertEqual([line for line in text.splitlines() if line.startswith("Exec")],
                         ["ExecStart=/py -E -s /kit/fleet.py browser-run", "ExecStartPost=/py -E -s /kit/fleet.py browser-ready"])
        self.assertIn("Environment=LANG=es_ES.UTF-8\nEnvironment=TZ=Europe/Madrid\n", fleet.browser_unit_text(
            "/py", "/kit", locale=("es_ES.UTF-8", "Europe/Madrid")))
        # with no team given, team.json as it is now: a new owner's language needs no helper restart
        with patch.object(fleet, "checkout_team", lambda: team("de-DE", "Europe/Madrid")):
            self.assertEqual(fleet.browser_locale(zones=zones), ("de_DE.UTF-8", "Europe/Madrid"))


# A stdio MCP server as the DevTools MCP answers: a log line and its answer in one write, and its tools in pages.
SERVER = r"""
import json, os, sys
pages = json.loads(sys.argv[1])
def out(*messages):
    os.write(1, "".join(json.dumps(m) + "\n" for m in messages).encode())
for line in sys.stdin:
    m = json.loads(line)
    note = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": "x"}}
    if m.get("method") == "initialize":
        out(note, {"jsonrpc": "2.0", "id": m["id"], "result": {"protocolVersion": "2025-06-18", "capabilities": {}}})
    elif m.get("method") == "tools/list":
        n = int((m.get("params") or {}).get("cursor") or 0)
        result = dict({"tools": pages[n]}, **({"nextCursor": str(n + 1)} if n + 1 < len(pages) else {}))
        out(note, {"jsonrpc": "2.0", "id": m["id"], "result": result})
"""


class ToolServer(unittest.TestCase):
    """D13 and round 9: a session gets the browser only from a tool server that gives exactly the pinned tools, each
    with its pinned input, by its own list."""

    def test_the_list_is_read_whole_across_pages_and_lines_that_came_together(self):
        pages = [[{"name": "list_pages", "inputSchema": {}}], [{"name": "evaluate_script", "inputSchema": {}}]]
        tools = fleet.mcp_tool_list(sys.executable, ["-c", SERVER, json.dumps(pages)], timeout=20)
        self.assertEqual([t["name"] for t in tools], ["list_pages", "evaluate_script"])

    def test_a_tool_or_an_input_that_is_not_pinned_gives_no_browser(self):
        schema = {"type": "object", "properties": {"url": {"type": "string"}}}
        tools = [{"name": "navigate_page", "inputSchema": schema}, {"name": "list_pages", "inputSchema": {}}]
        pinned = {t["name"]: fleet.tool_schema_hash(t["inputSchema"]) for t in tools}
        wider = dict(schema, properties=dict(schema["properties"], initScript={"type": "string"}))
        with patch.object(fleet, "BROWSER_MCP_TOOLS", pinned):
            self.assertIsNone(fleet.browser_tools_fault(tools))
            self.assertIn("more ['evaluate_script']",
                          fleet.browser_tools_fault(tools + [{"name": "evaluate_script", "inputSchema": {}}]))
            self.assertIn("fewer ['list_pages']", fleet.browser_tools_fault(tools[:1]))
            self.assertIn("navigate_page", fleet.browser_tools_fault([dict(tools[0], inputSchema=wider), tools[1]]))
            # a second navigate_page with another input would hide behind the first; a name that is no text
            self.assertIsNotNone(fleet.browser_tools_fault([dict(tools[0], inputSchema=wider)] + tools))
            self.assertIsNotNone(fleet.browser_tools_fault(tools + [{"name": ["x"], "inputSchema": {}}]))


class SetupCheck(unittest.TestCase):
    """S3: the machine check's item of the Browser box on Linux reads the parts and the port's live proof, in place of a
    fixed failure (the helper's own refusals are BrowserStart's)."""

    def item(self, conf=None, reading=None, port=9301, proof=True, places=None):
        reading = {"state": "ready", "chrome": "158.0.7400.1-1"} if reading is None else reading
        return fleet.lifecycle.browser_item(conf or CLAUDE, "fleet-ivy", reading, port=lambda user: port,
                                            proof=lambda user: proof, places=places)

    def test_the_item_is_ok_only_where_a_browser_task_can_start_now(self):
        """An activation that the item passes gives a task that its helper starts (fleet.Helper.browser_start): an
        item that said ok without the parts, the port or the proof would let an agent take work that fails."""
        self.assertEqual(self.item(), ("capability", "browser", "ok", "This agent's own Chrome is ready on this server."))
        frame = "This agent's own Chrome cannot start on this server yet: {}."
        for kwargs, reason in ((dict(conf=dict(CLAUDE, can=["browser"])), "it needs Claude Code or Codex, with its "
                                                                          "Shell box on"),
                               (dict(conf=dict(CLAUDE, runtime="opencode")), "it needs Claude Code or Codex, with its "
                                                                             "Shell box on"),
                               (dict(conf=dict(CODEX, start=fleet.lifecycle.APP_SERVER)), "it needs Claude Code or "
                                                                                          "Codex, with its Shell box on"),
                               (dict(reading={"state": "unsupported"}), "only a server with x86 Ubuntu 24.04 or 26.04 "
                                                                        "runs one"),
                               (dict(reading={"state": "missing"}), "its browser parts there are not ready yet"),
                               (dict(reading={"state": "table_missing"}), "its browser parts there are not ready yet"),
                               (dict(port=None), "its browser parts there are not ready yet"),
                               (dict(proof=False), "its browser parts there are not ready yet"),
                               # D6: the parts' own fault stays the reason on a server with no room too
                               (dict(places=0, proof=False), "its browser parts there are not ready yet")):
            self.assertEqual(self.item(**kwargs)[2:], ("failed", frame.format(reason)), kwargs)
        self.assertEqual(self.item(places=1)[2], "ok")
        # D6: a server whose room the hub counts at 0 starts no Chrome now. The item says so and is not_verified:
        # failed would keep the owner from activating an agent whose Browser box is a default (D1, hub.item_required)
        kind, ref, state, detail = self.item(places=0)
        self.assertEqual((state, detail), ("not_verified", frame.format("its server has no room for a browser now")))
        with patch.object(hub, "agents", lambda: {"ivy": CLAUDE}):
            self.assertIn("browser", CLAUDE["can"])
            self.assertFalse(hub.item_required("ivy", {"kind": kind, "ref": ref, "state": state}))
            self.assertTrue(hub.item_required("ivy", {"kind": kind, "ref": ref, "state": "failed"}))
        self.assertEqual(fleet.lifecycle.browser_item(CLAUDE, "fleet-ivy", None)[2:],
                         ("failed", frame.format("its browser parts there are not ready yet")))

    def test_the_helper_keeps_the_hub_s_count_of_places_for_the_check(self):
        """D6: the poll's count reaches the setup check through the helper. A helper that kept a hub's old 0 after
        the hub stopped saying, or took another value for a count, would fail the item on a server with room."""
        h = helper()
        h.keep_places(0)
        self.assertEqual(h.browser_places, 0)
        for none in (None, True, "0", {}):
            h.keep_places(none)
            self.assertIsNone(h.browser_places, none)
        h.keep_places(2)
        self.assertEqual(h.browser_places, 2)


class BrowserStart(unittest.TestCase):
    """Helper.browser_start (S2): the start of a browser task's own browser, and the check of its tool server."""

    def setUp(self):
        self.run_dir = tempfile.mkdtemp(prefix="fleet-browser-run-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.run_dir, True))
        self.flag = os.path.join(self.run_dir, "fleet-browser", "keep-session")
        self.unit = Path(os.path.expanduser("~"), ".config", "systemd", "user", "fleet_browser.service")
        with contextlib.suppress(FileNotFoundError):
            self.unit.unlink()                      # each test writes its unit itself (the module's home is shared)
        with contextlib.suppress(FileNotFoundError):
            os.remove(fleet.Helper.clears_file(types.SimpleNamespace(agent="ivy")))

    def start(self, keep=False, conf=CLAUDE, closed=False, port=9300, proof=True, ready=True, fault=None,
              answers=None, clears=None, windows=("T-1\tbrowser",), open_tasks=("T-1",), h=None, listed=None,
              hang=False, run=True, chrome="c-1"):
        """One browser_start of T-1 on a stand-in helper: (systemd's calls, what the tool check ran, the result or the
        refusal). At systemd's start, a line ("flag", whether the one-shot flag is there) and one ("caches", the
        count of cache deletes until then) follow it. `chrome` is the id of the Chrome that answers (None: none)."""
        caches = []

        def started(args):          # the unit's own program writes the screen key anew at each start (cmd_browser_run)
            calls.extend([("flag", os.path.exists(self.flag)), ("caches", len(caches))])
            key = os.path.join(self.run_dir, "fleet-browser", "screen-key")
            with open(key + ".new", "w", encoding="utf-8") as f:
                f.write(str(len(calls)))
            os.replace(key + ".new", key)
            return 0, ""
        calls, call = systemd(dict({"start": started}, **(answers or {})))
        checked = {}

        def tool_list(command, args, env=None, **_):
            checked.update(command=command, args=list(args), env={k: env[k] for k in fleet.BROWSER_MCP_SETTINGS})
            if listed is not None:
                listed.append(1)
            if hang:
                raise fleet.Refused("the browser's tool server gave no answer to tools/list in 90 s")
            return []
        h = h or helper(conf, browser_caches=lambda: caches.append(1), browser_clears=clears or (lambda port: None))
        h.open_tasks = list(open_tasks) if open_tasks is not None else None
        with patch.object(fleet, "browser_port", lambda user=None: port), \
                patch.object(fleet, "browser_proof_holds", lambda user: proof), \
                patch.object(fleet, "package_ready", lambda package: {"program": ["node"], "path": "/bin"} if ready
                             else None), patch.object(fleet, "package_install", lambda package: calls.append(
                                 ("install", package["name"]))), \
                patch.object(fleet, "mcp_tool_list", tool_list), patch.object(fleet, "browser_tools_fault", lambda t: fault), \
                patch.object(fleet, "systemctl_user", call), patch.object(fleet, "tmux", tmux_of(windows)), \
                patch.object(fleet, "chrome_answers", lambda port, wait=5.0: chrome), \
                patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.run_dir}):
            try:
                result = fleet.Helper.browser_start(h, "T-1", keep=keep, closed=closed, run=run)
            except fleet.Refused as e:
                result = e
        return calls, checked, result

    def name(self, task="T-1", chrome="c-1", db=DB, key=None):
        """The name of whose pages the agent's Chrome holds, as browser_start writes it: with the mark of the screen
        key of now, which a start of the unit wrote, unless `key` gives another."""
        folder = Path(self.run_dir, "fleet-browser")
        folder.mkdir(exist_ok=True)
        if not (folder / "screen-key").exists():
            (folder / "screen-key").write_text("key")
        st = (folder / "screen-key").stat()
        (folder / "pages-task").write_text(f"{db}\t{task}\t{chrome}\t{key or f'{st.st_ino}:{st.st_mtime_ns}'}\n")
        return folder / "pages-task"

    def test_no_browser_without_its_port_a_live_proof_or_the_pinned_tools(self):
        for kwargs in (dict(port=None), dict(proof=False), dict(fault="its tools are not the pinned ones")):
            calls, _, result = self.start(**kwargs)
            self.assertIsInstance(result, fleet.Refused, kwargs)
            self.assertFalse([c for c in calls if c[0] == "start"], kwargs)

    def test_only_a_terminal_session_with_its_shell_and_no_sandboxed_policy_gets_a_browser(self):
        """A closed session and an ACP session would not get the browser; and a Codex agent whose start policy is
        app-server runs in Codex's sandbox, whose browser task would get full access in a terminal (review round 1)."""
        grok = dict(CLAUDE, runtime="grok", start=lifecycle.RUNTIMES["grok"]["first_worker"])
        for kwargs in (dict(closed=True), dict(conf=grok), dict(conf=dict(CODEX, start=lifecycle.APP_SERVER)),
                       dict(conf=dict(CLAUDE, can=["browser"]))):
            calls, _, result = self.start(**kwargs)
            self.assertIsInstance(result, fleet.Refused, kwargs)
            self.assertFalse(calls, kwargs)
            # one rule with the hub (S3): what the hub admits a browser task for, the helper starts, and the reverse
            why = lifecycle.linux_browser_refusal(kwargs.get("conf", CLAUDE)) or \
                "a browser on a Linux server needs a session with the agent's shell, and this one is closed"
            self.assertEqual(str(result), f"{why}: its browser task does not start here", kwargs)
        self.assertEqual(self.start(conf=CODEX)[2], fleet.browser_tool(9300))

    def test_a_task_s_start_asks_for_no_chrome_while_the_poll_names_it_waiting(self):
        """S3 (D10): a task's session that starts while the last poll's `waits` names it (a new attempt at a usage
        limit's end, a task with no free place) asks browser_start for its tool only; any other start runs Chrome."""
        for seen, run in (({"T-7": "place"}, False), ({}, True)):
            h, asked = fleet.Helper("ivy", dict(CLAUDE)), {}
            h.browser_waits_seen = seen
            event = {"id": 9, "kind": "task", "task": "T-7", "text": "Read the page",
                     "extra": {"generation": "g", "attempt": 1, "needs": "browser"}}
            with patch.object(fleet.sys, "platform", "linux"), patch.object(h, "look", return_value=[]), \
                    patch.object(h, "say"), patch.object(h, "sync_checkout"), \
                    patch.object(fleet.Helper, "browser_start", lambda self, task, **kw: asked.update(kw) or {"t": 1}), \
                    patch("fleet.start_refusal", lambda *a, **k: None), patch("fleet.programs_wait", lambda *a, **k: None), \
                    patch("fleet.session_credential", return_value=None), patch("fleet.session_env", return_value={}), \
                    patch("fleet.session_command", return_value="true"), patch("fleet.mint_tokens", return_value=None), \
                    patch("fleet.start_window", lambda *a, **k: None), patch("fleet.http", return_value=(200, {})), \
                    patch("fleet.tmux", return_value=subprocess.CompletedProcess([], 0, "", "")):
                h.handle_events([event])
            self.assertIs(asked.get("run"), run, seen)

    def test_a_task_that_waits_at_its_start_gets_its_tool_and_no_chrome(self):
        """S3 (D10): a task whose session starts while the poll's `waits` names it (a new attempt after a usage limit,
        a task with no free place) starts no Chrome; at the wait's end its browser starts as a new one, with no page
        of an earlier task kept."""
        h = helper(CLAUDE)
        calls, _, result = self.start(h=h, run=False)
        self.assertEqual((calls, result), ([("is-active", "fleet_browser.service")], fleet.browser_tool(9300)))
        self.assertEqual((h.browser_waiting, h.browser_fresh), ({"T-1"}, {"T-1"}))
        # a Chrome that still runs is an earlier session's (no other browser window is open): it stops, so that the new
        # session reaches none of its pages
        for closed, wanted in ((True, fleet.browser_tool(9300)), (False, fleet.Refused)):
            ends = []
            h = helper(CLAUDE, browser_close=lambda closed=closed: ends.append(1) or closed)
            _, _, result = self.start(h=h, run=False, answers={"is-active": (0, "active\n")})
            self.assertEqual(len(ends), 1)          # Chrome's own close, which keeps its cookies (D10)
            self.assertTrue(result == wanted if closed else isinstance(result, wanted), (closed, result))
        again = helper(CLAUDE, browser_fresh=None)          # a restart of the helper reads the mark from its file
        self.assertEqual(fleet.Helper.fresh_tasks(again), {"T-1"})
        self.start(h=again)                                 # a start with its Chrome: its pages are its own from now on
        self.assertEqual(fleet.Helper.fresh_tasks(helper(CLAUDE, browser_fresh=None)), set())
        h = helper(CLAUDE)                                  # its next attempt starts in a wait: they stay its own
        self.start(h=h, run=False)
        self.assertEqual((h.browser_waiting, h.browser_fresh), ({"T-1"}, set()))
        for task, state, key in (("T-9", "inactive", None),       # another task's pages
                                 ("T-1", "failed", None),         # its own after crashes (D5)
                                 ("T-1", "activating", None),     # its own while systemd starts Chrome again
                                 ("T-1", "inactive", "1:1")):     # its own, and a start of the unit came since
            self.name(task, key=key)
            h = helper(CLAUDE, browser_close=lambda: True)
            self.start(h=h, run=False, answers={"is-active": (3, state + "\n")})
            self.assertEqual(h.browser_fresh, {"T-1"}, (task, state, key))
        with patch("builtins.open", side_effect=OSError(28, "No space left on device")):
            self.assertEqual(fleet.Helper.fresh_tasks(again, {"T-4"}), {"T-4"})     # a full disk stops no loop

    def test_one_browser_task_for_each_agent_at_a_time(self):
        """D9: two sessions on one Chrome share all its tabs, and a second start would stop the first task's Chrome
        and delete its pages. The window of a task that ended goes a while later: it holds nothing."""
        for windows, open_tasks, refused in ((("T-1\tbrowser", "T-2\tbrowser"), ["T-1", "T-2"], True),
                                             (("T-1\tbrowser", "T-2\tbrowser"), ["T-1"], False),
                                             (("T-1\tbrowser", "T-2\tbrowser"), None, True),     # before a poll
                                             (("T-1\tbrowser", "T-3\tnone", "home\t"), ["T-1", "T-3"], False),
                                             ((), ["T-1"], False), (None, ["T-1"], True)):
            calls, _, result = self.start(windows=windows, open_tasks=open_tasks)
            self.assertIs(isinstance(result, fleet.Refused), refused, (windows, open_tasks))
            self.assertIs(any(c[0] == "start" for c in calls), not refused, (windows, open_tasks))

    def test_the_tool_check_runs_once_for_each_package_and_command(self):
        """A tool server that hangs holds the helper's loop up to 90 s: a wait's end, or the next task, does not run
        the check again for the same package and the same command."""
        listed, h = [], helper(CLAUDE, browser_caches=lambda: None, browser_clears=lambda port: None)
        for _ in range(3):
            self.assertEqual(self.start(h=h, listed=listed)[2], fleet.browser_tool(9300))
        self.assertEqual(listed, [1])
        self.start(h=h, listed=listed, port=9301)          # another command: the check runs again
        self.assertEqual(listed, [1, 1])
        for hang in (False, True):          # its tools not the pinned ones, or a tool server that does not answer
            bad = helper(CLAUDE, browser_caches=lambda: None, browser_clears=lambda port: None)
            for clock, ran in ((1000.0, True), (1300.0, False), (1601.0, True)):     # a failed check: after 600 s
                runs = []
                with patch.object(fleet.time, "monotonic", lambda clock=clock: clock):
                    result = self.start(h=bad, listed=runs, fault=None if hang else "its tools are not the pinned ones",
                                        hang=hang)[2]
                self.assertIsInstance(result, fleet.Refused, (hang, clock))
                self.assertIs(bool(runs), ran, (hang, clock))

    def test_the_tool_server_installs_in_a_thread_while_the_start_waits(self):
        """The helper's loop never waits for a download (package_in_place's rule)."""
        calls, _, result = self.start(ready=False)
        self.assertIsInstance(result, fleet.Installing)
        self.assertEqual(calls, [("install", fleet.BROWSER_MCP_PACKAGE["name"])])
        folder = fleet.package_folder(lifecycle.mcp_package(fleet.BROWSER_SERVER, fleet.BROWSER_MCP_PACKAGE))
        with patch.dict(fleet.PACKAGE_INSTALLS, {folder: {"error": "no such version"}}):
            calls, _, result = self.start(ready=False)
            self.assertIn("no such version", str(result))
            self.assertNotIn(folder, fleet.PACKAGE_INSTALLS)            # the next start tries the install again

    def test_the_unit_is_written_when_it_changed_and_keeps_its_pages_at_a_waits_end_and_for_its_own_task(self):
        """D5: a task's start loses the profile's last pages, and a wait's end keeps them. A new attempt of the task
        whose pages the running Chrome holds goes on in that Chrome as it is (live, 20 November 2026: the owner passed
        a check by Take over, and the attempt after it, whose cache had gone cold, found a blank page)."""
        calls, _, tool = self.start()
        self.assertEqual(tool, fleet.browser_tool(9300))
        self.assertIn(("daemon-reload",), calls)
        self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)])       # a task's start: no pages, its caches
        self.assertEqual(self.unit.read_text(), fleet.browser_unit_text(locale=fleet.browser_locale()))
        calls, _, _ = self.start(keep=True)
        self.assertNotIn(("daemon-reload",), calls)          # the same text: no reload
        self.assertEqual(calls[-2:], [("flag", True), ("caches", 0)])        # a wait's end keeps its pages
        calls, _, _ = self.start(answers={"is-active": (3, "failed\n")})   # a flag that a start left goes before
        self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)])     # the next one, which keeps no page
        pages, cleared = Path(self.run_dir, "fleet-browser", "pages-task"), []
        self.assertEqual(pages.read_text().split("\t")[:3], [DB, "T-1", "c-1"])     # each start names its task
        calls, _, tool = self.start(answers=ACTIVE, clears=cleared.append)  # T-1's next attempt: its Chrome goes on
        self.assertEqual((tool, cleared), (fleet.browser_tool(9300), [9300]))         # after the clears that wait
        self.assertEqual([c for c in calls if c[0] in ("stop", "start")], [])
        self.assertIn(("reset-failed", "fleet_browser.service"), calls)    # its start count, as at a start (D5)
        for said, chrome in ((dict(task="T-9"), "c-1"),                    # another task's Chrome
                             (dict(db="ba9876543210"), "c-1"),             # the same number in another hub database
                             (dict(key="1:1"), "c-1"),                     # a start of the unit came since its name
                             (dict(), "c-2"),                              # a Chrome that systemd started again
                             (dict(), None)):                              # a Chrome that does not answer
            self.name(**said)
            calls, _, _ = self.start(answers=ACTIVE, chrome=chrome)
            self.assertIn(("stop", "fleet_browser.service"), calls, (said, chrome))
            self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)], (said, chrome))     # none of its pages
        self.name()
        calls, _, _ = self.start(chrome="c-2")               # its own Chrome ended with no crash: its pages come back,
        self.assertEqual(calls[-2:], [("flag", True), ("caches", 0)])
        self.assertEqual(pages.read_text().split("\t")[2], "c-2")          # and the name gives the new Chrome's id
        self.name(key="1:1")                                 # a start of the unit came since its name: no old page
        calls, _, _ = self.start()
        self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)])
        self.name(key="1:1")                                 # but a wait's end keeps its own task's pages, as before
        calls, _, _ = self.start(keep=True)
        self.assertEqual(calls[-2:], [("flag", True), ("caches", 0)])
        self.name(db="ba9876543210", key="1:1")              # and none of a task of the same number in another database
        calls, _, _ = self.start(keep=True)
        self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)])
        pages.write_text("garbage\n")                         # a name that names nobody keeps nothing
        calls, _, _ = self.start(keep=True)
        self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)])
        self.name()                                          # a task that is to start with a new browser (S3)
        calls, _, _ = self.start(h=helper(CLAUDE, browser_fresh={"T-1"}, browser_caches=lambda: None,
                                          browser_clears=lambda port: None))
        self.assertEqual(calls[-2], ("flag", False))
        calls, _, _ = self.start(answers={"is-active": (3, "failed\n")})   # after crashes (D5): no old page
        self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)])
        self.name("T-9")
        calls, _, _ = self.start(keep=True)                  # a wait's end keeps no page of another task's
        self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)])
        self.unit.write_text("[Unit]\n")                     # a release changed the unit: its Chrome goes on, and the
        calls, _, _ = self.start(answers=ACTIVE)             # new text holds from its next start
        self.assertIn(("daemon-reload",), calls)
        self.assertEqual([c for c in calls if c[0] in ("stop", "start")], [])
        fleet.browser_clears_write(fleet.Helper.clears_file(types.SimpleNamespace(agent="ivy")),
                                   {"7:a": {"origins": ["https://a.test"], "cookies": []}})
        calls, _, _ = self.start(keep=True)                  # a clear waits: the site's pages would load first
        self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)])

    def test_a_start_that_failed_or_a_clear_that_did_not_finish_stops_the_unit(self):
        def fails(port):
            raise fleet.Refused("the browser did not lose a login whose grant ended: Chrome did not answer")
        for kwargs, named in ((dict(answers={"start": (1, "")}, keep=True), False), (dict(clears=fails), False),
                              (dict(clears=fails, answers=ACTIVE), True)):     # its own Chrome, kept as it runs
            if named:
                self.name()
            calls, _, result = self.start(**kwargs)
            self.assertIsInstance(result, fleet.Refused)
            starts = [n for n, c in enumerate(calls) if c[0] == "start"]
            self.assertIn(("stop", "fleet_browser.service"), calls[starts[-1] if starts else 0:], kwargs)
            self.assertFalse(os.path.exists(self.flag), kwargs)
        # a start that keeps no page names nobody before it runs: when it fails before the unit's own program ran,
        # the next try keeps none of the old files either (here a crash's pause, D5)
        self.name()
        self.start(answers={"is-active": (3, "activating\n"), "start": (1, "")}, keep=True)
        calls, _, _ = self.start(keep=True)
        self.assertEqual(calls[-2:], [("flag", False), ("caches", 1)])

    def test_the_owners_take_over_ends_before_a_new_attempt_gets_its_chrome(self):
        """S6: the agent never goes on while the owner can still type on its screen. A start of Chrome ended his
        sharing with the screen; a Chrome that a new attempt keeps as it runs ends it on its own."""
        stops = []

        def running(args):          # the sharing ends at its stop; Chrome runs
            return (3, "inactive\n") if args[1] == "fleet_vnc.service" and stops else (0, "active\n")
        for answers, wanted in (({"is-active": running, "stop": lambda args: stops.append(args[1]) or (0, "")},
                                 fleet.browser_tool(9300)),
                                ({"is-active": (0, "active\n")}, fleet.Refused)):   # a sharing that does not end
            self.name()
            calls, _, result = self.start(answers=answers)
            self.assertIn(("stop", "fleet_vnc.service"), calls)
            self.assertTrue(result == wanted if isinstance(wanted, dict) else isinstance(result, wanted), result)
            self.assertNotIn(("stop", "fleet_browser.service"), calls)
        self.assertEqual(stops, ["fleet_vnc.service"])

    def test_a_start_that_fails_after_the_browser_ends_only_a_chrome_that_it_started(self):
        """A Chrome that the start of a new attempt kept as it ran keeps the task's pages for the next try (the sweep
        stops it where no window comes); one that it started ends, so that no Chrome waits for a session that never
        comes."""
        for kept, wanted in ((True, []), (False, ["close"])):
            h, closes = fleet.Helper("ivy", dict(CLAUDE)), []

            def start(self, task, kept=kept, **kw):
                self.browser_kept = task if kept else None
                return {"t": 1}
            event = {"id": 9, "kind": "task", "task": "T-7", "text": "Read the page",
                     "extra": {"generation": "g", "attempt": 2, "needs": "browser"}}
            with patch.object(fleet.sys, "platform", "linux"), patch.object(h, "look", return_value=[]), \
                    patch.object(h, "say"), patch.object(h, "sync_checkout"), \
                    patch.object(fleet.Helper, "browser_start", start), \
                    patch.object(fleet.Helper, "browser_close", lambda self: closes.append("close") or True), \
                    patch("fleet.start_refusal", lambda *a, **k: None), patch("fleet.programs_wait", lambda *a, **k: None), \
                    patch("fleet.session_credential", side_effect=OSError("the hub did not answer")), \
                    patch("fleet.http", return_value=(200, {})), \
                    patch("fleet.tmux", return_value=subprocess.CompletedProcess([], 0, "", "")):
                h.handle_events([event])
            self.assertEqual(closes, wanted, kept)

    def test_the_session_runs_the_tool_server_that_the_helper_checked(self):
        """Its command, its arguments and its variables, for Claude Code (its MCP file) and for Codex (its -c
        options), as the helper ran them for the check, under a name that no owner's server can have; its pinned
        tools only (Claude Code's allow list, Codex's enabled_tools); and no --chrome and no Chrome extension's tools
        for a browser task on Linux."""
        _, checked, tool = self.start()
        with patch.object(fleet.sys, "platform", "linux"), patch.object(fleet, "team_catalog", dict), \
                patch.object(fleet, "session_env", lambda *a, **k: {}), \
                patch.object(fleet, "package_ready", lambda package: {"program": ["node"], "path": "/bin"}):
            claude = shlex.split(fleet.session_command("ivy", CLAUDE, "read the page", task="T-1", needs="browser",
                                                       generation="g1", session="s1", browser=tool))
            codex = fleet.session_command("ivy", CODEX, "read the page", task="T-1", needs="browser",
                                          generation="g1", session="s1", browser=tool)
        self.assertIsNone(lifecycle.MCP_NAME.fullmatch(fleet.BROWSER_SERVER))
        server = json.loads(Path(claude[claude.index("--mcp-config") + 1]).read_text())["mcpServers"][fleet.BROWSER_SERVER]
        self.assertEqual({k: server[k] for k in ("command", "args", "env")}, checked)
        self.assertNotIn("--chrome", claude)
        allow = json.loads(claude[claude.index("--settings") + 1])["permissions"]["allow"]
        self.assertEqual(sorted(a for a in allow if "browser" in a or "chrome" in a),
                         sorted(f"mcp__{fleet.BROWSER_SERVER}__{name}" for name in fleet.BROWSER_MCP_TOOLS))
        envfile = re.match(r"\. (\S+) && rm -f ", codex).group(1)
        said = next(line for line in Path(envfile).read_text().splitlines() if line.startswith("set -- "))
        key = f"mcp_servers.{fleet.BROWSER_SERVER}."
        options = dict(w.split("=", 1) for w in shlex.split(said[7:]) if w.startswith(key))
        self.assertEqual({"command": json.loads(options[key + "command"]), "args": json.loads(options[key + "args"]),
                          "env": {k[len(key + "env."):]: json.loads(v) for k, v in options.items()
                                  if k.startswith(key + "env.")}}, checked)
        self.assertEqual(options[key + "default_tools_approval_mode"], '"approve"')
        self.assertEqual(json.loads(options[key + "enabled_tools"]), sorted(fleet.BROWSER_MCP_TOOLS))


class FakeChrome:
    """Chrome's DevTools as cdp_clear calls it: its pages, its cookies and each call. Like Chrome 158 (live, 17
    November 2026), it takes a cookie's delete, a storage clear and a navigation only in a page's session; on the
    browser's own target the clear answers "Internal error". `sticky`: the names of cookies that its delete leaves;
    `again`: the names of cookies that an open page of their site sets again, with a new value."""

    def __init__(self, cookies, pages=(), sticky=(), again=(), slow=0, odd=(), strict=True):
        self.cookies, self.sticky, self.again, self.calls = [dict(c) for c in cookies], set(sticky), set(again), []
        self.pages = {f"P{n}": url for n, url in enumerate(pages)}
        self.sessions, self.slow, self.closing, self.odd, self.limit = {}, slow, {}, list(odd), None
        self.limits, self.lost = [], set()          # the limit at each read of the cookies; the methods that fail
        self.strict = strict                        # no delete while a closed page is still listed

    def call(self, method, params=None, session=None):
        self.calls.append((method, params, session))
        if method in self.lost:
            raise fleet.CdpLost(f"{method}: DevTools ended the connection")
        if method == "Storage.getCookies":
            self.limits.append(None if self.limit is None else self.limit - time.monotonic())
            return {"cookies": [dict(c) for c in self.cookies]}
        if method == "Target.getTargets":
            for target in list(self.closing):           # a closed page goes from the list a moment later
                self.closing[target] -= 1
                if self.closing[target] < 0:
                    del self.closing[target]
            return {"targetInfos": self.odd + [{"targetId": k, "type": "page", "url": v} for k, v in self.pages.items()]
                    + [{"targetId": k, "type": "page", "url": "https://closing.test/"} for k in self.closing]}
        if method == "Target.createTarget":
            self.pages["OWN"] = params["url"]
            return {"targetId": "OWN"}
        if method == "Target.closeTarget":
            self.closing[params["targetId"]] = self.slow
            self.pages.pop(params["targetId"], None)
            return {"success": True}
        if method == "Target.attachToTarget":
            self.sessions[f"S-{params['targetId']}"] = params["targetId"]
            return {"sessionId": f"S-{params['targetId']}"}
        if method == "Target.detachFromTarget":
            return {}
        if session is None:
            raise fleet.CdpError(f"{method}: Internal error")
        if method == "Network.deleteCookies":
            assert not (self.strict and self.closing), "a cookie went while a closed page could still set it"
            same = lambda c: (c["name"], c["domain"], c["path"], c.get("partitionKey")) == \
                (params["name"], params["domain"], params["path"], params.get("partitionKey"))
            gone = [c for c in self.cookies if same(c) and c["name"] not in self.sticky]
            self.cookies = [c for c in self.cookies if c not in gone]
            site = lambda c: any(c["domain"].lstrip(".") in url for url in self.pages.values())       # embedded
            self.cookies += [dict(c, value=c.get("value", "") + "-new") for c in gone if c["name"] in self.again and site(c)]
        return {}


COOKIES = [{"name": "sid", "domain": ".practice.test", "path": "/", "value": "1"},
           {"name": "hostonly", "domain": "login.practice.test", "path": "/", "value": "2"},
           {"name": "deep", "domain": ".a.practice.test", "path": "/x", "value": "3"},
           {"name": "chips", "domain": ".practice.test", "path": "/", "value": "4",
            "partitionKey": {"topLevelSite": "https://shop.test", "hasCrossSiteAncestor": True}},
           {"name": "NID", "domain": ".google.com", "path": "/", "value": "5"},          # made by the sign-in's reCAPTCHA
           {"name": "NID", "domain": ".google.com", "path": "/", "value": "6",           # in the sign-in's partition
            "partitionKey": {"topLevelSite": "https://practice.test", "hasCrossSiteAncestor": True}},
           {"name": "NID", "domain": ".google.com", "path": "/", "value": "10",          # the same in another site's
            "partitionKey": {"topLevelSite": "https://other.test", "hasCrossSiteAncestor": True}},  # partition
           {"name": "SID", "domain": ".google.com", "path": "/", "value": "7"},          # the agent's own Google session
           {"name": "keep", "domain": "notpractice.test", "path": "/", "value": "8"},    # ends the same, no subdomain
           {"name": "keep", "domain": "127.0.0.1", "path": "/", "value": "9"}]


class BrowserClear(unittest.TestCase):
    """S2, from S5's record: when a site login's grant ends for the agent, its Chrome loses that login."""

    def test_a_grant_end_takes_the_sites_pages_cookies_and_storage_and_leaves_the_rest(self):
        chrome = FakeChrome(COOKIES, pages=("https://login.practice.test/account", "https://news.test/",
                                            "https://www.a.practice.test/x"), slow=3, odd=(None, "x"))
        clear = lifecycle.browser_clear_valid({"origins": ["https://login.practice.test/account?x=1"], "cookies": [
            {"name": "NID", "domain": ".google.com", "partitionKey": {"topLevelSite": "https://practice.test"}},
            {"name": "NID", "domain": ".google.com", "path": "/"}]})
        fleet.cdp_clear(chrome, "S", clear)
        self.assertEqual(sorted((c["name"], c["domain"], c["value"]) for c in chrome.cookies),
                         [("NID", ".google.com", "10"), ("SID", ".google.com", "7"), ("keep", "127.0.0.1", "9"),
                          ("keep", "notpractice.test", "8")])
        self.assertEqual(chrome.pages, {"P1": "https://news.test/"})        # the site's pages closed, and gone first
        self.assertIn(("Storage.clearDataForOrigin", {"origin": "https://login.practice.test", "storageTypes": "all"},
                       "S"), chrome.calls)
        closed = [n for n, c in enumerate(chrome.calls) if c[0] == "Target.closeTarget"]
        self.assertLess(max(closed), min(n for n, c in enumerate(chrome.calls) if c[0] == "Network.deleteCookies"))

    def test_a_page_that_takes_no_call_is_passed_over_and_the_clears_own_page_stays(self):
        """A page that is gone takes no close: the clear goes on, and its cookie check decides. The clear's own blank
        page stays, so that Chrome never closes its last window and ends."""
        chrome = FakeChrome(COOKIES, pages=("https://login.practice.test/", "https://www.practice.test/"))
        chrome.pages["OWN"] = "https://login.practice.test/x"     # the session took the clear's own page there
        call = chrome.call

        def gone(method, params=None, session=None):
            if method == "Target.closeTarget" and params["targetId"] == "P0":
                raise fleet.CdpError("Target.closeTarget: No target with given id found")
            return call(method, params, session)
        chrome.call = gone
        fleet.cdp_clear(chrome, "S", lifecycle.browser_clear_valid({"origins": ["https://login.practice.test"]}),
                        own="OWN")
        self.assertEqual(chrome.pages, {"P0": "https://login.practice.test/", "OWN": "https://login.practice.test/x"})
        self.assertNotIn("sid", [c["name"] for c in chrome.cookies])

    def test_one_clear_that_fails_stops_no_other(self):
        """A clear that cannot finish stays on the list, and the clears after it run (each in its own try); a clear
        that is not of the contract is dropped and said so."""
        h = helper()
        path = fleet.Helper.clears_file(h)
        fleet.browser_clears_write(path, {"7:a": {"origins": ["https://login.practice.test"], "cookies": []},
                                          "8:b": {"origins": ["https://other.test"], "cookies": []},
                                          "9:c": {"origins": ["file:///etc"]}})
        self.addCleanup(lambda: [os.path.exists(f) and os.remove(f) for f in (path, fleet.Helper.clears_file(h, True))])
        chrome = FakeChrome(COOKIES, sticky={"sid"})

        class Opened:
            def __init__(self, port, timeout):
                pass

            def __enter__(self):
                return chrome

            def __exit__(self, *_):
                pass
        with patch.object(fleet, "Cdp", Opened), self.assertRaisesRegex(fleet.Refused, "7: 1 cookie"):
            fleet.Helper.browser_clears(h, 9300)
        self.assertEqual(list(fleet.browser_clears_read(path)), ["7:a"])
        self.assertEqual(fleet.browser_clears_read(fleet.Helper.clears_file(h, True)), {"done": ["8:b", "9:c"]})
        self.assertIn("browser clear 9: an invalid clear in the list was dropped", h.said)
        self.assertIsNotNone(chrome.limit)                  # the run has a time limit of its own
        self.assertIn("OWN", chrome.pages)                  # its own page, the last one, stays: Chrome would end
        self.assertTrue(chrome.limits and all(0 < left <= 60 for left in chrome.limits), chrome.limits)
        self.assertGreater(chrome.limits[0], 50)            # a limit of the run: 60 s from its start
        chrome.pages["P9"] = "https://news.test/"
        fleet.browser_clears_write(path, {"10:d": {"origins": ["https://other.test"], "cookies": []}})
        with patch.object(fleet, "Cdp", Opened):
            fleet.Helper.browser_clears(h, 9300)
        self.assertEqual(chrome.pages, {"P9": "https://news.test/"})       # with another page there, it goes

    def test_a_cookie_that_stays_with_its_value_fails_the_clear_and_one_set_again_does_not(self):
        clear = lifecycle.browser_clear_valid({"origins": ["https://login.practice.test"]})
        with self.assertRaises(fleet.CdpError):
            fleet.cdp_clear(FakeChrome(COOKIES, sticky={"sid"}), "S", clear)
        # another site's page that embeds the cleared site stays open, and the embedded part sets its cookie again
        chrome = FakeChrome(COOKIES, pages=("https://news.test/?embed=practice.test",), again={"sid"})
        fleet.cdp_clear(chrome, "S", clear)
        self.assertIn(("sid", "1-new"), [(c["name"], c["value"]) for c in chrome.cookies])

    def test_only_an_origin_is_a_clear(self):
        valid = lifecycle.browser_clear_valid
        self.assertEqual(valid({"origins": ["https://a.test:443/login?next=1", "http://A.test:8088/", "http://b.test:80",
                                            "https://a.test"], "cookies": None})["origins"],
                         ["https://a.test", "http://a.test:8088", "http://b.test"])
        self.assertEqual(valid({"origins": ["https://a.test"], "cookies": [
            {"name": "x", "domain": "W.test", "partitionKey": {"topLevelSite": "https://a.test"}}]})["cookies"],
            [{"name": "x", "domain": "w.test", "partitionKey": {"topLevelSite": "https://a.test"}}])
        for extra in ({"origins": []}, {"origins": ["https://u@a.test"]}, {"origins": ["file:///etc"]},
                      {"origins": ["javascript:alert(1)"]}, {"origins": ["https://a.test"] * 51},
                      {"origins": ["https://a.test"], "cookies": [{"domain": "a.test"}]},
                      {"origins": ["https://a.test"], "cookies": [{"name": "x", "domain": "a.test/x"}]},
                      {"origins": ["https://a.test"], "cookies": [{"name": "x", "domain": "a.test", "path": "x"}]}, [],
                      {"origins": ["https://a.test./"]}, {"origins": ["https://bücher.test"]}):     # S5 checks the same
            self.assertIsNone(valid(extra), extra)

    def clears(self, h, chrome, clears, write=None):
        """One run of browser_clears on `chrome` with this list; `write` stands for browser_clears_write."""
        fleet.browser_clears_write(fleet.Helper.clears_file(h), clears)
        self.addCleanup(lambda: [os.path.exists(f) and os.remove(f)
                                 for f in (fleet.Helper.clears_file(h), fleet.Helper.clears_file(h, True))])

        class Opened:
            def __init__(self, port, timeout):
                pass

            def __enter__(self):
                return chrome

            def __exit__(self, *_):
                pass
        with patch.object(fleet, "Cdp", Opened), patch.object(fleet, "browser_clears_write",
                                                              write or fleet.browser_clears_write):
            fleet.Helper.browser_clears(h, 9300)

    def test_a_lost_connection_ends_the_run_and_its_clears_stay(self):
        """After a lost connection nothing on it is to be read (a frame cut off): no later clear runs on it."""
        chrome = FakeChrome(COOKIES)
        chrome.lost = {"Network.deleteCookies"}
        h = helper()
        with self.assertRaisesRegex(fleet.Refused, "ended the connection"):
            self.clears(h, chrome, {"7:a": {"origins": ["https://login.practice.test"], "cookies": []},
                                    "8:b": {"origins": ["https://practice.test"], "cookies": []}})
        self.assertEqual(list(fleet.browser_clears_read(fleet.Helper.clears_file(h))), ["7:a", "8:b"])
        self.assertEqual(sum(1 for c in chrome.calls if c[0] == "Network.deleteCookies"), 1)

    def test_a_done_mark_comes_before_the_clear_leaves_the_list(self):
        """A run that stops between the two writes runs the clear again (it does nothing more), never not at all; a
        done file that is not a list is none; no agent's list file is another agent's done file."""
        h, real = helper(), fleet.browser_clears_write

        def list_fails(path, clears):
            if path == fleet.Helper.clears_file(h):
                raise OSError("No space left on device")
            real(path, clears)
        fleet.browser_clears_write(fleet.Helper.clears_file(h, True), {"done": "7:a"})     # not a list
        with self.assertRaises(fleet.Refused):
            self.clears(h, FakeChrome(COOKIES), {"7:a": {"origins": ["https://login.practice.test"], "cookies": []}},
                        write=list_fails)
        self.assertEqual(fleet.browser_clears_read(fleet.Helper.clears_file(h, True)), {"done": ["7:a"]})
        for a, b in (("done-x", "x"), ("x-done", "x"), ("x", "done-x")):
            self.assertNotEqual(fleet.Helper.clears_file(types.SimpleNamespace(agent=a)),
                                fleet.Helper.clears_file(types.SimpleNamespace(agent=b), True), (a, b))

    def test_the_own_page_stays_while_a_page_that_the_clear_closed_is_on_its_way_out(self):
        """Also after a clear that closed a page and then failed (a cookie stayed): Chrome ends with its last window."""
        for sticky in ((), ("sid",)):
            chrome = FakeChrome(COOKIES, pages=("https://login.practice.test/",), slow=10 ** 6,   # never gone in time
                                strict=False, sticky=sticky)
            with patch.object(fleet, "BROWSER_PAGES_WAIT", 0.2), contextlib.suppress(fleet.Refused):
                self.clears(helper(), chrome, {"7:a": {"origins": ["https://login.practice.test"], "cookies": []}})
            self.assertIn("OWN", chrome.pages, sticky)

    def test_a_clear_that_fails_is_tried_after_its_back_off_and_not_at_each_event(self):
        tries = []

        def fails(port):
            tries.append(port)
            raise fleet.Refused("the browser did not lose a login whose grant ended: Chrome did not answer")
        h = helper(browser_clears=fails)
        self.addCleanup(lambda: os.path.exists(fleet.Helper.clears_file(h)) and os.remove(fleet.Helper.clears_file(h)))
        with patch.object(fleet.sys, "platform", "linux"), patch.object(fleet, "browser_port", lambda user=None: 9300), \
                patch.object(fleet, "systemctl_user", systemd({"is-active": (0, "active\n")})[1]):
            for event, clock in ((7, 1000.0), (8, 1005.0), (9, 1010.0)):
                with patch.object(fleet.time, "monotonic", lambda clock=clock: clock):
                    fleet.Helper.browser_clear(h, event, {"origins": [f"https://s{event}.test"]})
        self.assertEqual(tries, [9300])

    def test_a_clear_is_kept_once_waits_for_the_next_start_and_comes_again_while_chrome_starts(self):
        applied = []
        h = helper(browser_clears=applied.append)
        extra = {"origins": ["https://login.practice.test"]}
        path = fleet.Helper.clears_file(h)
        with contextlib.suppress(FileNotFoundError):
            os.remove(path)
        with patch.object(fleet.sys, "platform", "linux"), patch.object(fleet, "browser_port", lambda user=None: 9300):
            with patch.object(fleet, "systemctl_user", systemd()[1]):
                fleet.Helper.browser_clear(h, 7, extra)
                fleet.Helper.browser_clear(h, 7, extra)                 # the same event, tried again
                fleet.Helper.browser_clear(h, 7, {"origins": ["https://other.test"]})   # an id that came again
                fleet.Helper.browser_clear(h, 8, {"origins": ["file:///etc"]})          # no clear: left
            self.assertEqual(sorted(c["origins"][0] for c in fleet.browser_clears_read(path).values()),
                             ["https://login.practice.test", "https://other.test"])
            self.assertEqual(applied, [])
            with patch.object(fleet, "systemctl_user", systemd({"is-active": (3, "activating\n")})[1]):
                fleet.Helper.browser_clear(h, 9, extra)             # systemd restarts Chrome: a round applies it later
            self.assertEqual(applied, [])
            with patch.object(fleet, "systemctl_user", systemd({"is-active": (0, "active\n")})[1]):
                fleet.Helper.browser_clear(h, 9, extra)
            self.assertEqual(applied, [9300])
        done = fleet.Helper.clears_file(h, done=True)
        self.addCleanup(lambda: os.path.exists(done) and os.remove(done))
        mark = next(m for m in fleet.browser_clears_read(path) if m.startswith("9:"))
        fleet.browser_clears_write(done, {"done": [mark]})
        fleet.browser_clears_write(path, {})
        with patch.object(fleet.sys, "platform", "linux"), patch.object(fleet, "systemctl_user", systemd()[1]):
            fleet.Helper.browser_clear(h, 9, extra)             # its clear ran, and the event came again: no rerun
        self.assertEqual(fleet.browser_clears_read(path), {})


class BrowserCloseAndWaits(unittest.TestCase):
    """D10: a wait for the owner or for a usage limit gives the browser's place back, and its end brings the pages
    back (live: Chrome restores them after a hard stop too, with --hide-crash-restore-bubble)."""

    def test_a_close_that_chrome_did_not_take_stops_the_unit(self):
        for took, states, stopped, closed in ((True, ["active", "inactive"], False, True),
                                              (False, ["active", "active", "inactive"], True, True),
                                              (False, ["active"] * 9, True, False),
                                              (False, ["no bus"], False, True),     # no user manager: no unit
                                              (False, ["no medium"], True, False),  # nothing known: not closed
                                              (False, ["timeout"], True, False)):    # out of time: nothing known
            seen = list(states)

            def is_active(args, seen=seen):         # each answer in turn; the last one stays
                word = seen.pop(0) if len(seen) > 1 else seen[0]
                return {"no bus": (1, "", "Failed to connect to bus: No such file or directory"),
                        "no medium": (1, "", "Failed to connect to bus: No medium found"),
                        "timeout": (1, "", "Command '['systemctl']' timed out after 30 seconds")}.get(word, (0, word + "\n"))
            calls, call = systemd({"is-active": is_active})
            with patch.object(fleet, "systemctl_user", call), patch.object(fleet, "browser_port", lambda user=None: 9300), \
                    patch.object(fleet, "cdp_browser_close", lambda port: took), patch.object(fleet, "BROWSER_CLOSE_WAIT", 0.3):
                self.assertIs(fleet.Helper.browser_close(types.SimpleNamespace()), closed, states)
            self.assertIs(("stop", "fleet_browser.service") in calls, stopped, states)

    def test_a_user_manager_that_no_bus_reaches_round_after_round_runs_no_unit(self):
        """A manager that restarts misses one try; one that is gone misses each: after BROWSER_NO_BUS rounds the
        browser counts as closed, and its wait gives its place back."""
        _, call = systemd({"is-active": (1, "", "Failed to connect to bus: Connection refused")})
        h = types.SimpleNamespace()
        _, active = systemd({"is-active": (0, "active\n")})
        with patch.object(fleet, "browser_port", lambda user=None: 9300), \
                patch.object(fleet, "cdp_browser_close", lambda port: False):
            with patch.object(fleet, "systemctl_user", call):
                self.assertFalse(fleet.Helper.browser_close(h))
            with patch.object(fleet, "systemctl_user", active):     # a round in which the bus answered
                self.assertFalse(fleet.Helper.browser_close(h))
            with patch.object(fleet, "systemctl_user", call):       # the count starts again
                self.assertEqual([fleet.Helper.browser_close(h) for _ in range(fleet.BROWSER_NO_BUS)],
                                 [False] * (fleet.BROWSER_NO_BUS - 1) + [True])

    def test_an_install_that_runs_waits_a_short_time_each_round(self):
        """Installing is no failure: its wait does not grow, so the browser starts soon after the install ends."""
        tries = []
        h = helper()

        def act():
            tries.append(1)
            raise fleet.Installing("the browser's tool server is being installed")
        for clock in (1000.0, 1015.0, 1030.0):
            fleet.Helper.browser_try(h, "T-1", act, now=clock)
        self.assertEqual((len(tries), h.browser_retry["T-1"]), (3, (15, 1045.0)))

    def waits(self, h, waits, windows=("T-1\tbrowser", "T-2\tnone", "T-3\t"), active=False, platform="linux",
              clock=1000.0):
        with patch.object(fleet, "tmux", tmux_of(windows)), patch.object(fleet.sys, "platform", platform), \
                patch.object(fleet.time, "monotonic", lambda: clock), \
                patch.object(fleet, "systemctl_user", systemd({"is-active": (0, "active\n" if active else "inactive\n")})[1]):
            fleet.Helper.browser_waits(h, waits)

    def test_a_wait_closes_the_browser_and_its_end_opens_it_with_its_pages(self):
        done, closes = [], [False, True]
        starts = [fleet.Refused("no live proof"), OSError("No space left on device"), None]

        def start(task, keep=False):
            done.append(("start", task, keep))
            fault = starts.pop(0)
            if fault:
                raise fault
        h = helper(browser_close=lambda: done.append("close") or closes.pop(0), browser_start=start)
        h.open_tasks = ["T-1", "T-2"]
        self.waits(h, {"T-1": "secret", "T-2": "secret"})               # Chrome did not end: after its back-off
        self.waits(h, {"T-1": "secret", "T-2": "secret"}, clock=1005.0)  # not yet
        self.waits(h, {"T-1": "secret", "T-2": "secret"}, clock=1015.0)
        self.waits(h, {"T-1": "secret"}, active=True, clock=1020.0)     # it waits still: nothing more
        for clock in (1030.0, 1040.0, 1046.0, 1100.0):                  # its end: a refused start and a fault of the
            self.waits(h, {"T-2": "limit"}, clock=clock)                # machine, each after its back-off, then it runs
        self.waits(h, {"T-2": "limit"}, active=True, clock=1200.0)      # and then not again
        self.assertEqual(done, ["close", "close"] + [("start", "T-1", True)] * 3)     # T-2 is no browser task
        self.assertEqual(h.browser_waits_seen, {"T-2": "limit"})       # a session that starts now reads it (S3)
        self.assertEqual(h.said, ["T-1: its browser did not end for its wait; its browser step is tried again in 15 s",
                                  "T-1: no live proof; its browser step is tried again in 15 s",
                                  "T-1: OSError: No space left on device; its browser step is tried again in 30 s"])

    def test_a_task_that_started_with_no_chrome_gets_a_new_browser_at_its_wait_s_end(self):
        """S3: its session started during a wait (browser_start's run=False), so the profile's last session is an earlier
        task's: its browser starts without the kept pages, and the mark goes."""
        done = []
        h = helper(browser_start=lambda task, keep=False: done.append((task, keep)))
        fleet.Helper.fresh_tasks(h, {"T-1"})
        h.browser_waiting = {"T-1"}
        self.waits(h, {})
        self.assertEqual((done, fleet.Helper.fresh_tasks(h)), ([("T-1", False)], set()))

    def test_a_wait_that_closes_a_chrome_that_systemd_starts_again_keeps_no_page(self):
        """D5: after a crash systemd starts the unit again a moment later, and its own program deletes the session
        files then. A close for a wait in that moment stops it first, so the wait's end starts Chrome with no page."""
        done = []
        h = helper(browser_close=lambda: True, browser_start=lambda task, keep=False: done.append((task, keep)))
        for waits, state in (({"T-1": "secret"}, "activating"), ({}, "inactive")):
            with patch.object(fleet, "tmux", tmux_of(("T-1\tbrowser",))), patch.object(fleet.sys, "platform", "linux"), \
                    patch.object(fleet, "systemctl_user", systemd({"is-active": (3, state + "\n")})[1]):
                fleet.Helper.browser_waits(h, waits)
        self.assertEqual((done, fleet.Helper.fresh_tasks(h)), ([("T-1", False)], set()))

    def test_the_name_follows_a_chrome_that_systemd_started_again_for_its_task(self):
        """D5 and D9: systemd starts the agent's Chrome again after a crash or a kill at its cap, and the task goes on
        in the new Chrome: its name follows it while the task's window is the one browser window, so that the task's
        next attempt keeps that Chrome. Without the window, or before the unit runs again, the name stays."""
        run = tempfile.mkdtemp(prefix="fleet-browser-run-")
        self.addCleanup(lambda: __import__("shutil").rmtree(run, True))
        folder = Path(run, "fleet-browser")
        folder.mkdir()
        (folder / "screen-key").write_text("key")
        st = (folder / "screen-key").stat()
        old, new = f"{DB}\tT-1\tc-1\t1:1\n", f"{DB}\tT-1\tc-2\t{st.st_ino}:{st.st_mtime_ns}\n"
        other = "ba9876543210\tT-1\tc-1\t1:1\n"           # the same number in another hub database
        for windows, state, before, wanted, generation in (
                ((), "active", old, old, DB), (("T-1\tbrowser",), "activating", old, old, DB),
                (("T-1\tbrowser",), "active", old, new, DB),
                (("T-1\tbrowser",), "active", "\n", new, DB),            # a name of nobody
                (("T-1\tbrowser",), "active", None, new, DB),            # no name: an older helper's Chrome
                (("T-1\tbrowser",), "active", other, other, DB),
                (("T-1\tbrowser",), "active", None, None, "ba9876543210")):   # the window of another database's task
            if before is None:
                (folder / "pages-task").unlink(missing_ok=True)
            else:
                (folder / "pages-task").write_text(before)
            with patch.object(fleet, "tmux", tmux_of(windows, f"{generation}:1")), \
                    patch.object(fleet.sys, "platform", "linux"), \
                    patch.object(fleet, "systemctl_user", systemd({"is-active": (0, state + "\n")})[1]), \
                    patch.object(fleet, "chrome_answers", lambda port, wait=5.0: "c-2"), \
                    patch.object(fleet, "browser_port", lambda user=None: 9300), \
                    patch.dict(os.environ, {"XDG_RUNTIME_DIR": run}):
                fleet.Helper.browser_waits(helper(), {})
            said = (folder / "pages-task").read_text() if (folder / "pages-task").exists() else None
            self.assertEqual(said, wanted, (windows, state, before, generation))

    def test_the_poll_says_which_tasks_chrome_this_helper_closed(self):
        """S3 (D10): a wait's place goes back once no Chrome of it runs: the tasks whose Chrome the helper closed, and
        every open task while its unit is not active; from the first poll on, and nothing on a Mac."""
        for unit, waiting, wanted in (("active\n", {"T-1"}, "T-1"), ("inactive\n", {"T-1"}, "T-1%2CT-2%2CT-3"),
                                      ("active\n", None, ""), ("inactive\n", set(), "T-2%2CT-3"),
                                      ("inactive\n", None, "")):       # no browser work: no question to systemd
            h = helper(browser_waiting=waiting, browser_tasks=["T-2"] if waiting == set() else [])
            h.browser_waiting = waiting
            h.open_tasks = ["T-2", "T-3"]
            with patch.object(fleet, "systemctl_user", systemd({"is-active": (0, unit)})[1]), \
                    patch.object(fleet.sys, "platform", "linux"):
                self.assertEqual(fleet.Helper.browser_closed(h), "&browser_closed=" + wanted, (unit, waiting))
        with patch.object(fleet.sys, "platform", "darwin"):
            self.assertEqual(fleet.Helper.browser_closed(helper()), "")

    def test_a_helper_that_started_again_opens_the_browser_of_an_open_task_that_does_not_wait(self):
        for active, open_tasks, wanted in ((False, ["T-1"], [("start", "T-1", True)]), (True, ["T-1"], []),
                                           (False, ["T-9"], [])):        # a task that ended keeps its window a while
            done = []
            h = helper(browser_waiting=None, browser_close=lambda: done.append("close"),
                       browser_start=lambda task, keep=False: done.append(("start", task, keep)))
            h.open_tasks = open_tasks
            self.waits(h, {}, active=active)
            self.assertEqual(done, wanted, (active, open_tasks))
            self.assertEqual(h.browser_waiting, set())

    def test_a_clear_that_came_during_systemds_own_restart_runs_at_a_round_with_chrome_active(self):
        applied = []
        h = helper(browser_clears=applied.append, browser_close=lambda: True, browser_start=lambda *a, **k: None)
        fleet.browser_clears_write(fleet.Helper.clears_file(h), {"7:a": {"origins": ["https://a.test"], "cookies": []}})
        self.addCleanup(os.remove, fleet.Helper.clears_file(h))
        with patch.object(fleet, "browser_port", lambda user=None: 9300):
            self.waits(h, {})
            self.assertEqual(applied, [])
            self.waits(h, {}, active=True)
        self.assertEqual(applied, [9300])

    def test_nothing_is_decided_on_what_is_not_known(self):
        # a poll that does not say, a tmux that does not answer, a Mac (whose browser is the owner's Chrome), and a
        # helper before the poll that names its open tasks
        for waits, kwargs, open_tasks in ((None, {}, ["T-1"]), ({"T-1": "secret"}, dict(windows=None), ["T-1"]),
                                          ({"T-1": "secret"}, dict(platform="darwin"), ["T-1"]),
                                          ({"T-1": "secret"}, {}, None)):
            done = []
            h = helper(browser_close=lambda: done.append("close"), browser_start=lambda *a, **k: done.append("start"))
            h.open_tasks = open_tasks
            self.waits(h, waits, **kwargs)
            self.assertEqual(done, [], (waits, kwargs))


class ScreenAndReady(unittest.TestCase):
    """The unit's own start (browser-run) and its check (browser-ready)."""

    def test_the_screen_s_number_goes_with_the_screen(self):
        """S7: browser-run starts the agent's screen with screen_arguments, and its display file is there while Chrome
        runs and goes when Chrome ends or the unit stops: a file left behind names a number that another user's X
        server can hold, and the take-over's x11vnc and the live view's capture read that file. The key stays: its
        mark says that no start came since the helper named the Chrome's pages, also after Chrome ended."""
        folder = tempfile.mkdtemp(prefix="fleet-run-")
        self.addCleanup(lambda: __import__("shutil").rmtree(folder, True))
        shown, started, seen, handlers = os.path.join(folder, "display"), [], [], {}
        key = os.path.join(folder, "screen-key")

        class Process:
            def __init__(self, args, **kw):
                started.append(args)

            def wait(self):
                seen.append((Path(shown).read_text(), os.path.exists(key)))
                return 0
            terminate = kill = lambda self: None
        with patch.object(fleet, "browser_folder", lambda: folder), patch.object(fleet, "browser_profile", lambda: folder), \
                patch.object(fleet, "browser_port", lambda user=None: 9301), \
                patch.object(fleet.subprocess, "run", lambda *a, **kw: Path(key).write_text("xauth wrote it")), \
                patch.object(fleet.subprocess, "Popen", Process), patch.object(fleet, "screen_display", lambda fd: "7"), \
                patch.object(fleet.signal, "signal", lambda sign, handler: handlers.update({sign: handler})), \
                self.assertRaises(SystemExit):
            fleet.cmd_browser_run(None)
        fd = started[0][started[0].index("-displayfd") + 1]
        self.assertEqual(started[0], fleet.screen_arguments(os.path.join(folder, "screen-key"), fd))
        self.assertEqual(started[0][-3:], ["-screen", "0", "1280x800x24"])
        self.assertIn("--window-size=1280,800", started[2])         # one size for the screen and Chrome's window
        self.assertEqual((seen, os.path.exists(shown), os.path.exists(key)), ([("7", True)], False, True))
        Path(shown).write_text("7")                 # a stop of the unit (SIGTERM) while Chrome runs
        Path(key).write_text("xauth wrote it")
        with patch.object(fleet.signal, "signal", lambda *a: None), patch.object(fleet.os, "kill", lambda *a: None):
            handlers[fleet.signal.SIGTERM](fleet.signal.SIGTERM, None)
        self.assertEqual((os.path.exists(shown), os.path.exists(key)), (False, True))

    def test_the_screens_number_is_read_to_its_newline(self):
        """Xvfb writes the number and its newline in two writes; a pipe closed after the first ended it in half of all
        starts (live, 17 November 2026)."""
        read_end, write_end = os.pipe()
        failed = []

        def xvfb():
            try:
                os.write(write_end, b"3")
                time.sleep(0.3)
                os.write(write_end, b"\n")
            except OSError as e:
                failed.append(e)
            finally:
                os.close(write_end)
        writer = threading.Thread(target=xvfb)
        writer.start()
        self.assertEqual(fleet.screen_display(read_end, wait=5), "3")
        os.close(read_end)
        writer.join()
        self.assertEqual(failed, [])
        read_end, write_end = os.pipe()
        os.write(write_end, b"4")                                       # and never its newline
        self.assertIsNone(fleet.screen_display(read_end, wait=0.3))
        os.close(read_end)
        os.close(write_end)

    def test_a_start_deletes_both_copies_of_the_session_unless_a_waits_end_left_its_flag_for_it(self):
        """D5: Chrome 157 and later keep an encrypted copy beside the plain one (probe 2); a flag serves one start."""
        profile = tempfile.mkdtemp(prefix="fleet-profile-")
        self.addCleanup(lambda: __import__("shutil").rmtree(profile, True))
        flag = os.path.join(profile, "keep-session")
        for keep in (True, False):
            for name in ("Sessions", "Sessions_Encrypted"):
                os.makedirs(os.path.join(profile, "Default", name, "x"), exist_ok=True)
            if keep:
                open(flag, "w").close()
            self.assertIs(fleet.drop_session_files(profile, flag), not keep)
            self.assertEqual([os.path.isdir(os.path.join(profile, "Default", n)) for n in ("Sessions", "Sessions_Encrypted")],
                             [keep, keep])
            self.assertFalse(os.path.exists(flag))

    def test_only_a_listener_of_the_units_own_processes_makes_it_ready(self):
        """D11: with the port taken by another process of the agent, Chrome listens on [::1] and that process answers
        on 127.0.0.1, so only a listening socket that a process of this unit's own cgroup holds counts."""
        root = tempfile.mkdtemp(prefix="fleet-ready-")
        self.addCleanup(lambda: __import__("shutil").rmtree(root, True))
        proc, cgroups = os.path.join(root, "proc"), os.path.join(root, "cgroup")
        unit = "/user.slice/user-1002.slice/user@1002.service/app.slice/fleet_browser.service"
        os.makedirs(os.path.join(proc, "self"))
        Path(proc, "self", "cgroup").write_text(f"0::{unit}\n")
        os.makedirs(cgroups + unit)
        Path(cgroups + unit, "cgroup.procs").write_text("100\n101\n")
        for pid, target in (("100", "socket:[555]"), ("101", "/dev/null")):
            os.makedirs(os.path.join(proc, pid, "fd"))
            os.symlink(target, os.path.join(proc, pid, "fd", "7"))
        with patch.object(fleet, "browser_port", lambda user=None: 9300):
            with patch.object(fleet, "listening_inodes", lambda port, uid=None: {"555"}):
                self.assertIsNone(fleet.cmd_browser_ready(None, wait=2, proc=proc, cgroups=cgroups))
            with patch.object(fleet, "listening_inodes", lambda port, uid=None: {"999"}):
                with self.assertRaises(SystemExit):
                    fleet.cmd_browser_ready(None, wait=0.3, proc=proc, cgroups=cgroups)

    def test_the_kernels_whole_list_of_sockets_is_read(self):
        """An agent with many sockets pushed another agent's listener past the first 4 MiB of /proc/net/tcp, which
        was all that was read (a review of 17 November 2026)."""
        head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        row = "{:4d}: {} 00000000:0000 {} 00000000:00000000 00:00000000 00000000  {}  0 {}\n"
        many = "".join(row.format(n, "0100007F:C000", "01", 1003, 1000 + n) for n in range(50000))  # over 4 MiB
        tcp = head + many + row.format(1, "0100007F:2454", "0A", 1002, 81) + row.format(2, "00000000:2454", "0A", 1003, 82) \
            + row.format(3, "0100007F:2455", "0A", 1002, 83)
        self.assertGreater(len(tcp), 1 << 22)
        opener = lambda *_a, **_k: io.StringIO(tcp)
        self.assertEqual(fleet.listening_inodes(9300, 1002, opener=opener), {"81"})
        self.assertEqual(fleet.listening_inodes(9300, opener=opener), {"81", "82"})


class DevTools(unittest.TestCase):
    """fleet.Cdp, the helper's own DevTools client (S2), against a stand-in Chrome on a port of this machine."""

    def chrome(self, frames, path="/devtools/browser/abc", hold=None):
        """A one-connection stand-in: /json/version, then the WebSocket upgrade, then `frames` (bytes) after the
        first message it reads; `hold` seconds before each byte, for a peer that drips. Returns its port and what it
        read."""
        server = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(server.close)
        port, got = server.getsockname()[1], []

        def serve():
            for _ in range(2):
                with contextlib.suppress(OSError):
                    conn, _ = server.accept()
                    with conn:
                        request = conn.recv(65536).decode("latin-1")
                        if "/json/version" in request.split("\r\n", 1)[0]:
                            body = json.dumps({"webSocketDebuggerUrl": f"ws://127.0.0.1:{port}{path}"}).encode()
                            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                                         + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
                            continue
                        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                     b"Connection: Upgrade\r\n\r\n")
                        got.append(conn.recv(65536))
                        for byte in (frames if hold else [frames]):
                            if hold:
                                time.sleep(hold)
                            conn.sendall(byte if isinstance(byte, bytes) else bytes([byte]))
                        with contextlib.suppress(OSError):
                            got.append(conn.recv(65536))
        threading.Thread(target=serve, daemon=True).start()
        return port, got

    @staticmethod
    def frame(data, opcode=0x1, fin=True):
        data = data if isinstance(data, bytes) else json.dumps(data).encode()
        size = len(data)
        head = bytes([(0x80 if fin else 0) | opcode])
        head += bytes([size]) if size < 126 else bytes([126]) + size.to_bytes(2, "big") if size < 65536 else \
            bytes([127]) + size.to_bytes(8, "big")
        return head + data

    def test_a_call_reads_its_answer_past_events_pings_and_frames_of_each_length(self):
        big = {"id": 1, "result": {"cookies": [{"name": "c", "value": "v" * 70000}]}}       # a length of 8 bytes
        whole = self.frame(big)
        frames = self.frame({"method": "Target.targetCreated", "params": {}}) + self.frame(b"", 0x9) + \
            self.frame({"method": "Network.x", "params": {"y": "z" * 300}}) + \
            self.frame(whole[10:40000], 0x1, fin=False) + self.frame(whole[40000:], 0x0)    # in two parts
        port, got = self.chrome(frames)
        with patch.object(fleet, "listening_inodes", lambda port, uid=None: {"1"}):
            with fleet.Cdp(port, 5) as cdp:
                self.assertEqual(cdp.call("Storage.getCookies"), big["result"])
        sent = got[0]                                       # one text frame, masked, as a client's must be
        self.assertEqual((sent[0], bool(sent[1] & 0x80)), (0x81, True))
        mask, data = sent[2:6], sent[6:6 + (sent[1] & 0x7F)]
        self.assertEqual(json.loads(bytes(b ^ mask[i % 4] for i, b in enumerate(data)))["method"], "Storage.getCookies")

    def test_an_error_a_drip_another_users_port_or_a_strange_address_ends_in_cdp_error(self):
        port, _ = self.chrome(self.frame({"id": 1, "error": {"message": "Internal error"}}))
        with patch.object(fleet, "listening_inodes", lambda port, uid=None: {"1"}):
            with fleet.Cdp(port, 5) as cdp:
                with self.assertRaisesRegex(fleet.CdpError, "Internal error"):
                    cdp.call("Storage.clearDataForOrigin")
                cdp.limit = time.monotonic() - 1           # a run of calls that ran out of its time sends nothing
                with self.assertRaisesRegex(fleet.CdpLost, "ran out of its time"):
                    cdp.call("Browser.getVersion")
            port, _ = self.chrome(b"")                          # a call that gets no answer ends at the run's limit
            with fleet.Cdp(port, 5) as cdp:
                cdp.limit, started = time.monotonic() + 0.3, time.monotonic()
                with self.assertRaises(fleet.CdpLost):
                    cdp.call("Browser.getVersion")
                self.assertLess(time.monotonic() - started, 2)
            port, _ = self.chrome(self.frame({"id": 1, "result": {}}), hold=0.2)    # a byte now and then
            started = time.monotonic()
            with fleet.Cdp(port, 1) as cdp, self.assertRaises(fleet.CdpError):
                cdp.call("Browser.getVersion")
            self.assertLess(time.monotonic() - started, 3)
            server = socket.create_server(("127.0.0.1", 0))      # an address answer that comes a byte at a time
            self.addCleanup(server.close)

            def drip():
                with contextlib.suppress(OSError):
                    conn, _ = server.accept()
                    with conn:
                        conn.recv(65536)
                        for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + b" " * 100:
                            time.sleep(0.2)
                            conn.sendall(bytes([byte]))
            threading.Thread(target=drip, daemon=True).start()
            started = time.monotonic()
            with self.assertRaises(fleet.CdpError):
                fleet.Cdp(server.getsockname()[1], 1)
            self.assertLess(time.monotonic() - started, 3)
            port, _ = self.chrome(b"", path="/devtools/browser/abc HTTP/1.1\r\nX-Header: 1")
            with self.assertRaises(fleet.CdpError):
                fleet.Cdp(port, 2)
        port, _ = self.chrome(b"")
        with patch.object(fleet, "listening_inodes", lambda port, uid=None: set()), self.assertRaises(fleet.CdpError):
            fleet.Cdp(port, 2)                                  # no listener of this agent's own uid: no connection


class ProofGate(unittest.TestCase):
    """fleet.browser_proof_holds, D11: a helper starts no Chrome without a current verdict `holds` of its own."""

    def test_only_a_fresh_verdict_of_this_user_for_the_ports_as_they_are_now(self):
        folder = tempfile.mkdtemp(prefix="fleet-proof-")
        self.addCleanup(lambda: __import__("shutil").rmtree(folder, True))
        ports, proof = os.path.join(folder, "ports"), os.path.join(folder, "state")
        Path(ports).write_text("fleet-ivy 9300 5910\n")
        version = __import__("hashlib").sha256(b"fleet-ivy 9300 5910\n").hexdigest()
        for text, age, user, holds in ((f"{version}\nfleet-ivy holds\n", 10, "fleet-ivy", True),
                                       (f"{version}\nfleet-ivy holds\n", 10, "fleet-kai", False),   # another's
                                       (f"{version}\nfleet-ivy open\n", 10, "fleet-ivy", False),
                                       (f"{'0' * 64}\nfleet-ivy holds\n", 10, "fleet-ivy", False),  # another table
                                       (f"{version}\nfleet-ivy holds\n", 901, "fleet-ivy", False),  # too old
                                       (f"{version}\nfleet-ivy holds\n", -61, "fleet-ivy", False),  # from the future
                                       (f"fleet-ivy holds\n{version}\n", 10, "fleet-ivy", False)):
            Path(proof).write_text(text)
            now = os.path.getmtime(proof) + age
            self.assertIs(fleet.browser_proof_holds(user, ports=ports, proof=proof, now=now), holds, (text, age, user))
        os.remove(proof)
        self.assertFalse(fleet.browser_proof_holds("fleet-ivy", ports=ports, proof=proof))


class TakeOver(unittest.TestCase):
    """Build plan 04, S6 (D7): the sharing of the agent's screen for the owner's take-over. One viewer on loopback with no
    clipboard and a one-time password that x11vnc reads from a file and deletes; never on an AI provider's page; and
    the stop at his answer, acknowledged only once systemd says that the unit ended."""

    PAGES = [{"type": "page", "url": "https://shop.example/check"}, {"type": "service_worker", "url": "https://x/"}]

    def setUp(self):
        self.folder = tempfile.mkdtemp(prefix="fleet-takeover-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.folder, True))

    def test_the_screen_keeps_its_picture_from_other_users(self):
        """Measured 21 November 2026 (x86 Ubuntu 24.04, Chrome 158): with MIT-SHM on the agent's Xvfb, Chrome kept its
        window's picture in a memory segment of mode 606 that another agent's OS user read and could write. The screen
        starts with no MIT-SHM and no TCP. It keeps its abstract socket: a name that Xvfb does not hold, another user
        can bind, and X clients try it first (a review of 21 November 2026)."""
        args = fleet.screen_arguments("/run/key", 7)
        self.assertEqual(args[:3], ["Xvfb", "-auth", "/run/key"])
        joined = " ".join(args)
        for pair in ("-extension MIT-SHM", "-nolisten tcp", "-displayfd 7"):
            self.assertIn(pair, joined)
        self.assertNotIn("-nolisten local", joined)

    def test_the_sharing_is_one_viewer_on_loopback_with_no_clipboard_and_its_password_from_a_file(self):
        args = fleet.vnc_arguments("7", "/run/key", 5911, "/run/vnc-password")
        for flag in ("-norc", "-nocmds", "-localhost", "-noipv6", "-nosel", "-noremote", "-novncconnect", "-once",
                     "-noshm"):         # -noshm: no picture of the screen in a memory segment that others read
            self.assertIn(flag, args)
        self.assertEqual(args[args.index("-passwdfile") + 1], "rm:/run/vnc-password")
        self.assertEqual(args[args.index("-rfbport") + 1], "5911")
        self.assertFalse({"-forever", "-shared", "-passwd", "-nopw"} & set(args))
        unit = fleet.vnc_unit_text(python="/usr/bin/python3", kit="/kit")
        self.assertIn("ExecStart=/usr/bin/python3 -E -s /kit/fleet.py vnc-run\n", unit)
        self.assertIn("Restart=no\n", unit)
        self.assertNotIn("[Install]", unit)             # never enabled: only the helper starts it

    def test_vnc_run_starts_x11vnc_only_on_a_running_screen_with_a_new_password(self):
        ran = []
        with patch.object(fleet, "browser_folder", lambda: self.folder), \
                patch.object(fleet.lifecycle, "screen_port", lambda user=None: 5911), \
                patch.object(fleet.os, "execv", lambda program, args: ran.append((program, args))):
            # only the display file names a screen: a key that a dead screen left names a number that another OS
            # user's X server can hold, and x11vnc would connect to it
            Path(self.folder, "screen-key").write_bytes(b"\x01\x00\x00\x03box\x00\x017\x00\x12MIT-MAGIC-COOKIE-1")
            with patch.object(fleet.subprocess, "run", side_effect=AssertionError("no program lists the key")), \
                    self.assertRaisesRegex(SystemExit, "screen does not run"):
                fleet.cmd_vnc_run(None)
            Path(self.folder, "display").write_text("7")
            with self.assertRaisesRegex(SystemExit, "no new one-time password"):
                fleet.cmd_vnc_run(None)
            Path(self.folder, fleet.VNC_PASSWORD).write_text("Ab3dEf7h\n")
            fleet.cmd_vnc_run(None)
            with patch.object(fleet.lifecycle, "screen_port", lambda user=None: None), \
                    self.assertRaisesRegex(SystemExit, "no screen-sharing port"):
                fleet.cmd_vnc_run(None)
        self.assertEqual(ran, [("/usr/bin/x11vnc", fleet.vnc_arguments(
            "7", os.path.join(self.folder, "screen-key"), 5911, os.path.join(self.folder, fleet.VNC_PASSWORD)))])

    def x_server(self, sockets, display, cookie, size=(4, 2)):
        """A stand-in for the agent's X server on the socket file of `display`: it takes the protocol's setup with the
        screen's cookie and answers GetImage of the root window. Returns what each client sent."""
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(os.path.join(sockets, f"X{display}"))
        listener.listen(8)
        self.addCleanup(listener.close)
        got, (w, h) = [], size
        pad = lambda b: b + b"\0" * (-len(b) % 4)

        def serve():
            while True:
                try:
                    client, _ = listener.accept()
                except OSError:
                    return
                with client:
                    client.settimeout(5)
                    try:
                        hello = client.recv(4096)
                        got.append(hello)
                        if cookie not in hello:
                            client.sendall(struct.pack("<BBHHH", 0, 0, 11, 0, 0))
                            continue
                        vendor = b"stand-in"
                        screen = struct.pack("<IIIIIHHHHHHIBBBB", 0x123, 0, 0, 0, 0, w, h, 1, 1, 1, 1, 0, 0, 0, 24, 0)
                        body = struct.pack("<IIIIHHBBBBBBBBI", 0, 0, 0, 0, len(vendor), 0xffff, 1, 1, 0, 0, 32, 32, 8,
                                           255, 0) + pad(vendor) + struct.pack("<BBBxI", 24, 32, 32, 0) + screen
                        client.sendall(struct.pack("<BBHHH", 1, 0, 11, 0, len(body) // 4) + body)
                        ask = client.recv(4096)
                        got.append(ask)
                        code, kind, _, root, x, y, aw, ah, planes = struct.unpack("<BBHIhhHHI", ask)
                        if (code, kind, root, x, y, aw, ah) != (73, 2, 0x123, 0, 0, w, h):
                            continue
                        client.sendall(struct.pack("<BBHII20x", 1, 24, 2, w * h, 0) + b"BGRx" * (w * h))
                    except OSError:
                        pass
        threading.Thread(target=serve, daemon=True).start()
        return got

    def test_the_capture_gives_a_frame_of_the_agent_s_own_screen_that_the_hub_takes(self):
        """Build plan 04, S7: the live view's capture program reads the screen that browser-run started (its display's
        socket file, with its cookie) with the X protocol's GetImage, makes a JPEG of it through ffmpeg by its path,
        and prints the line that the hub takes as a frame. It gives no line (the view then waits) where the picture is
        not one whole JPEG of at most 1 MiB, and while the screen is not this task's own: the Chrome's pages are named
        for another task or for an earlier start of the unit (an earlier task's Chrome would show under this task), the
        unit does not run, or the process at the other end of the socket is not this OS user's. That last one gets no
        byte of the cookie: another user's X server there would get the screen's key, and the owner would see its
        picture under this task."""
        jpeg, ran = b"\xff\xd8\xff" + b"screen" * 9 + b"\xff\xd9", []
        shots = [(0, jpeg), (1, jpeg), (0, jpeg[:-2]), (0, b"PNG" + jpeg), (0, jpeg[:-2] + b"x" * (1 << 20) + jpeg[-2:])]

        def run(args, **kw):
            ran.append((args, kw))
            code, out = shots.pop(0)
            return subprocess.CompletedProcess(args, code, out, b"")
        key, cookie = os.path.join(self.folder, "screen-key"), bytes(range(16))
        field = lambda b: len(b).to_bytes(2, "big") + b
        Path(key).write_bytes(b"".join(                 # xauth's file: display 0 with another cookie, then display 7
            b"\x01\x00" + field(b"box") + field(number) + field(b"MIT-MAGIC-COOKIE-1") + field(data)
            for number, data in ((b"0", b"\xee" * 16), (b"7", cookie))))
        sockets = tempfile.mkdtemp(prefix="x", dir="/tmp")           # short: a socket's path holds 104 characters
        self.addCleanup(lambda: __import__("shutil").rmtree(sockets, True))
        got = self.x_server(sockets, 7, cookie)
        said = {"pages": ("db", "T-4", "chrome-1", "5:9"), "mark": "5:9", "unit": "active", "peer": os.getuid()}
        task = types.SimpleNamespace(db="db", task="T-4")
        with patch.object(fleet, "browser_folder", lambda: self.folder), \
                patch.object(fleet.subprocess, "run", run), \
                patch.object(fleet, "browser_pages_read", lambda: said["pages"]), \
                patch.object(fleet, "screen_key_mark", lambda: said["mark"]), \
                patch.object(fleet, "browser_unit_state", lambda: said["unit"]), \
                patch.object(fleet, "peer_uid", lambda sock: said["peer"]), \
                patch.object(fleet, "X_SOCKETS", sockets), patch.object(fleet.time, "sleep", lambda s: None):
            self.assertIsNone(fleet.screen_frame(self.folder, "db", "T-4"))         # no display is written
            Path(self.folder, "display").write_text("7")
            for change in (dict(pages=("db", "T-5", "chrome-1", "5:9")), dict(pages=("db2", "T-4", "chrome-1", "5:9")),
                           dict(pages=None), dict(pages=()), dict(mark="6:1"), dict(unit="inactive"), dict(unit=""),
                           dict(peer=os.getuid() + 1)):
                with patch.dict(said, change):
                    self.assertIsNone(fleet.screen_frame(self.folder, "db", "T-4"), change)
            Path(self.folder, "display").write_text("9")
            self.assertIsNone(fleet.screen_frame(self.folder, "db", "T-4"))         # no screen listens there
            Path(self.folder, "display").write_text("7")
            time.sleep(0.2)
            self.assertEqual((ran, [g for g in got if g]), ([], []))    # no picture made; the screen got no byte
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                fleet.cmd_screen_capture(task, rounds=3)        # a frame, then two rounds with none: one line
            line = json.loads(out.getvalue())
            self.assertEqual((out.getvalue().count("\n"), len(ran)), (1, 3))
            others = [fleet.screen_frame(self.folder, "db", "T-4") for _ in range(2)]
        args, kw = ran[0]
        self.assertTrue(any(cookie in g for g in got))
        self.assertEqual((args[0], args[args.index("-i") + 1], args[-1], kw["input"]),
                         ("/usr/bin/ffmpeg", "-", "-", b"BGRx" * 8))       # the screen's own picture, of its own size
        self.assertEqual((args[args.index("-video_size") + 1], args[args.index("-pixel_format") + 1]), ("4x2", "bgr0"))
        self.assertNotIn("x11grab", args)               # it puts the picture in a memory segment of mode 777
        frames = __import__("desktop").Frames()
        frames.view("k", line["captured_at"])
        self.assertTrue(frames.put("k", line, line["captured_at"]))
        self.assertEqual(__import__("base64").b64decode(line["image"]), jpeg)
        self.assertEqual(others, [None, None])

    def press(self, pages=None, browser="active", listens=True, taken=True, cdp_fault=None, fault=None, keep=False,
              helper_h=None):
        """One takeover_open on a stand-in helper. Returns (what it posted, systemctl's calls, its lines, the mode of the
        password's file at the start)."""
        posted, modes, secret = [], [], os.path.join(self.folder, fleet.VNC_PASSWORD)

        def start(args):            # x11vnc reads the file at its start and deletes it
            modes.append(oct(os.stat(secret).st_mode & 0o777))
            if listens:
                os.remove(secret)
            return 0, ""
        calls, call = systemd({"is-active": (0, browser + "\n"), "start": start})

        class FakeCdp:
            def __init__(self, port, timeout):
                if cdp_fault:
                    raise cdp_fault

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def call(self, method, params=None):
                return {"targetInfos": pages if pages is not None else TakeOver.PAGES}

        def http(method, path, body=None, timeout=10):
            posted.append((path, dict(body)))
            if fault:
                raise fault
            return 200, {"taken": taken}
        h = helper_h or helper()
        with patch.object(fleet, "systemctl_user", call), patch.object(fleet, "Cdp", FakeCdp), \
                patch.object(fleet, "http", http), patch.object(fleet, "browser_folder", lambda: self.folder), \
                patch.object(fleet.lifecycle, "browser_port", lambda user=None: 9301), \
                patch.object(fleet.lifecycle, "screen_port", lambda user=None: 5911), \
                patch.object(fleet, "listening_inodes", lambda port, uid=None: {7} if listens and port == 5911 else set()), \
                patch.object(fleet, "VNC_LISTEN_WAIT", 0.5), patch.object(fleet.sys, "platform", "linux"), \
                patch.object(fleet.os.path, "expanduser", lambda p: p.replace("~", self.folder)):
            fleet.Helper.takeover_open(h, {"nonce": "n" * 24, "need": 5})
        return (posted, calls, h) if keep else (posted, calls, h.said, modes)

    def test_a_press_starts_the_sharing_with_a_new_password_and_answers_once(self):
        posted, calls, said, modes = self.press()
        self.assertEqual(len(posted), 1)
        path, body = posted[0]
        self.assertEqual((path, body["nonce"], body["port"]), ("/helper/takeover/ivy", "n" * 24, 5911))
        self.assertRegex(body["password"], r"\A[A-Za-z0-9]{8}\Z")
        self.assertEqual(modes, ["0o600"])
        self.assertLess(calls.index(("stop", "fleet_vnc.service")), calls.index(("start", "fleet_vnc.service")))
        self.assertFalse(any(body["password"] in line for line in said), said)
        self.assertFalse(os.path.exists(os.path.join(self.folder, fleet.VNC_PASSWORD)))
        self.assertNotEqual(self.press()[0][0][1]["password"], body["password"])      # each press a new one

    def test_a_providers_page_or_no_browser_opens_nothing(self):
        for kind, fault, browser, reason in (
                ([{"type": "page", "url": "https://claude.ai/login"}], None, "active", "provider"),
                ([{"type": "iframe", "url": "https://auth.openai.com/authorize"}], None, "active", "provider"),
                (None, None, "inactive", "no_browser"),
                (None, fleet.CdpError("no process of this agent listens"), "active", "no_browser"),
                ([{"type": "page", "url": "http://[::1"}], None, "active", "provider")):   # fails closed
            posted, calls, _, _ = self.press(pages=kind, browser=browser, cdp_fault=fault)
            self.assertEqual(posted[0][1], {"nonce": "n" * 24, "refused": reason}, reason)
            self.assertNotIn(("start", "fleet_vnc.service"), calls, reason)
        posted, calls, _, _ = self.press(pages=[{"type": "page", "url": "https://platform.claude.com/keys"}])
        self.assertIn("password", posted[0][1])         # a provider's API console is no sign-in (provider_site)

    def test_a_start_that_fails_stops_and_answers_screen_at_once(self):
        """A sharing that does not listen in time, and a start whose file step fails (the unit's file or the password's,
        a full disk), answer `screen` to the press at once, with no sharing (an earlier press's sharing ends too) and no
        password file left: else the owner waits out the press's whole time and reads that the screen did not open in
        time."""
        posted, calls, _, _ = self.press(listens=False)
        self.assertEqual(posted[0][1], {"nonce": "n" * 24, "refused": "screen"})
        self.assertEqual(calls[-1], ("stop", "fleet_vnc.service"))
        self.assertFalse(os.path.exists(os.path.join(self.folder, fleet.VNC_PASSWORD)))

        unit = os.path.join(self.folder, ".config", "systemd", "user", "fleet_vnc.service")
        Path(unit).write_text("an older unit\n")
        os.makedirs(unit + ".new")      # its new text cannot be written: an error before the stop of the sharing before
        posted, calls, said, _ = self.press()
        self.assertEqual(posted, [("/helper/takeover/ivy", {"nonce": "n" * 24, "refused": "screen"})])
        self.assertNotIn(("start", "fleet_vnc.service"), calls)
        self.assertEqual(calls[-1], ("stop", "fleet_vnc.service"))
        self.assertTrue(any("could not start (IsADirectoryError)" in line for line in said), said)
        os.rmdir(unit + ".new")

        def full(path, text):
            with open(path, "w", encoding="utf-8") as f:
                f.write(text[:3])
            raise OSError(28, "No space left on device")
        with patch.object(fleet, "write_private", full):
            posted, calls, said, _ = self.press()
        self.assertEqual(posted, [("/helper/takeover/ivy", {"nonce": "n" * 24, "refused": "screen"})])
        self.assertNotIn(("start", "fleet_vnc.service"), calls)
        self.assertFalse(os.path.exists(os.path.join(self.folder, fleet.VNC_PASSWORD)))
        self.assertTrue(any("could not start (OSError)" in line for line in said), said)

    def test_a_press_is_answered_once_also_when_its_ack_failed(self):
        """A pending takeover_open that a later poll hands out again (its ack failed) starts nothing: a second start
        would end the viewer that the owner types into."""
        posted, calls, h = self.press(keep=True)
        self.assertEqual(calls.count(("start", "fleet_vnc.service")), 1)
        posted2, calls2, _ = self.press(helper_h=h, keep=True)
        self.assertEqual((posted2, calls2), ([], []))

    def test_a_press_that_nobody_waits_for_any_more_stops_the_sharing(self):
        posted, calls, said, _ = self.press(taken=False)
        self.assertIn("password", posted[0][1])
        self.assertEqual(calls[-1], ("stop", "fleet_vnc.service"))
        import http.client
        posted, calls, said, _ = self.press(fault=http.client.IncompleteRead(b""))   # a fault that it did not name
        self.assertEqual(calls[-1], ("stop", "fleet_vnc.service"))                  # answered once: no second start

    def test_the_close_returns_only_once_systemd_says_that_the_unit_ended(self):
        Path(self.folder, fleet.VNC_PASSWORD).write_text("left\n")
        for state, ends in (("active", False), ("deactivating", False), ("", False), ("inactive", True),
                            ("failed", True)):
            calls, call = systemd({"is-active": (0 if state == "active" else 3, state + "\n")})
            h = helper()
            with patch.object(fleet, "systemctl_user", call), patch.object(fleet, "browser_folder", lambda: self.folder), \
                    patch.object(fleet.sys, "platform", "linux"):
                if ends:
                    fleet.Helper.takeover_close(h, {"need": 5})
                else:
                    with self.assertRaises(fleet.Refused):
                        fleet.Helper.takeover_close(h, {"need": 5})
            self.assertEqual(calls[0], ("stop", "fleet_vnc.service"), state)
        self.assertFalse(os.path.exists(os.path.join(self.folder, fleet.VNC_PASSWORD)))


class HubWaits(unittest.TestCase):
    """hub.browser_waits, the poll's `waits` (D10): the open tasks of an agent that wait long with nothing to do."""

    def test_a_wait_for_the_owner_or_a_usage_limit_and_no_other(self):
        from test_ui_api import quick
        folder = tempfile.mkdtemp(prefix="fleet-hub-waits-")
        self.addCleanup(lambda: __import__("shutil").rmtree(folder, True))
        db = quick(sqlite3.connect(os.path.join(folder, "hub.db"), check_same_thread=False))
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        team = {"addresses": {"owner": "127.0.0.1", "hub": "127.0.0.2"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "hub", "can": []},
                           "ivy": {"role": "worker", "runtime": "claude", "machine": "hub", "can": ["browser"]},
                           "kai": {"role": "worker", "runtime": "claude", "machine": "hub", "can": ["shell"]}}}
        with patch.object(hub, "DB", db), patch.object(hub, "TEAM", team), patch.object(hub, "team_read", lambda: team):
            hub.DB.executescript(hub.SCHEMA)
            hub.migrate()
            made = []
            for owner, state, waiting_on in (("ivy", "input-required", "N-5"), ("ivy", "input-required", "M-9"),
                                             ("ivy", "working", None), ("ivy", "completed", None),
                                             ("kai", "input-required", "N-6")):
                needs = "browser" if owner == "ivy" else "none"
                text = hub.t_create_task("manager", {"owner": owner, "title": "Read the page",
                                                     "done_when": "the answer is delivered", "needs": needs})
                made.append(int(text.split()[1][2:].rstrip(".")))
                hub.q("UPDATE tasks SET state=?, waiting_on=? WHERE id=?", (state, waiting_on, made[-1]))
            secret, colleague, working = (f"T-{n}" for n in made[:3])
            self.assertEqual(hub.browser_waits("ivy"), {secret: "secret"})      # a colleague's answer comes soon
            # S6 (D10): a take-over's wait keeps its Chrome and its place, also under a usage limit: he needs that screen
            text = hub.t_create_task("manager", {"owner": "ivy", "title": "Solve the page", "done_when": "solved",
                                                 "needs": "browser"})
            taking = int(text.split()[1][2:].rstrip("."))
            nid = hub.ins("INSERT INTO needs(id,title,why,todo,raised,by,kind,takeover_task) VALUES(7,'t','','',?,"
                          "'ivy','takeover',?)", (hub.now(), taking))
            hub.q("UPDATE tasks SET state='input-required', waiting_on=? WHERE id=?", (f"N-{nid}", taking))
            self.assertEqual(hub.browser_waits("ivy"), {secret: "secret"})
            self.assertEqual(hub.browser_waits("kai"), {})                      # no Browser box: nothing to close
            hub.q("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('ivy',?,?,1)",
                  (hub.now(), hub.now() + 3600))
            self.assertEqual(hub.browser_waits("ivy"), {secret: "limit", colleague: "limit", working: "limit"})


if __name__ == "__main__":
    unittest.main()

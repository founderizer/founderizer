"""The helper updates the agent runtimes of its OS user by itself (lifecycle.Lifecycle.update_runtimes).

The owner, 22 October 2026: "they should probably update themselves too, right?" On that day the machines ran Claude
Code 2.1.285 to 2.1.301 and Codex 0.158.0 to 0.160.0, where the vendors gave 2.1.308 and 0.163.0: Claude Code's own
background updater was not keeping them current, and Codex has none. So the helper takes the vendor's newest version
at most every six hours and only while no session of its user works, checks it with the reading it already makes for
the hub, and puts the previous version back when that check fails, so that a bad version cannot break a machine.

Stubbed commands: no installer, runtime or hub runs. The one check of real tmux uses a socket of its own.
"""
import fcntl
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import fleet
import hub
import lifecycle
import onboard
from leftovers import scratch_home, tmux_socket
from lifecycle import RUNTIME_INSTALL_WAIT, RUNTIME_UPDATE_EVERY, Lifecycle, Updating

HELP = ("Usage: claude [options] [command] [prompt]\n  --model <model>  Model for the current session. Provide an "
        "alias for the latest model (e.g. 'sonnet' or 'opus').\n  --effort <level>  Effort level (low, medium, high)\n")
OPTIONS = [{"model": "gpt-6", "display_name": "GPT-6", "default": True, "efforts": ["low"], "default_effort": "low"}]
BINARY = b"\x7fELF\x02\x01\x01 a vendor's program"


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


class Machine:
    """The runtimes of one OS user as the stubbed commands see them: what is installed in ~/.local/bin, what the
    vendor gives, and which versions fail the check."""

    def __init__(self, home):
        self.home = home
        self.installed = {"claude": "2.1.301", "codex": "0.160.0"}
        self.newest = {"claude": "2.1.308", "codex": "0.163.0"}
        self.bad = set()            # versions whose model options cannot be read (claude --help, codex model/list)
        self.silent = set()         # versions whose --version answers nothing
        self.install_fails = False  # the vendor's update exits 1 and changes nothing
        self.rollback_fails = False
        self.scripts = []           # (script, timeout, cwd) of every shell command
        self.could_start = []       # whether a session could start while each of them ran
        self.system = {}            # runtimes in /usr/bin, with their versions: a system package, an npm install as root
        self.lc = None
        for name in self.installed:
            self.put(name, BINARY)

    def put(self, name, content):
        os.makedirs(os.path.join(self.home, ".local", "bin"), exist_ok=True)
        with open(self.path(name), "wb") as f:
            f.write(content)

    def path(self, name):
        return os.path.join(self.home, ".local", "bin", name)

    def which(self, name):
        if os.path.exists(self.path(name)):
            return self.path(name)
        return "/usr/bin/" + name if name in self.system else None

    def __call__(self, argv, timeout=20, cwd=None):
        if argv[:2] == ["/bin/sh", "-c"]:
            return self.shell(argv[2], timeout, cwd)
        name = os.path.basename(argv[0])
        if argv[0] == "/usr/bin/" + name and name in self.system and argv[1:] == ["--version"]:
            return 0, ("codex-cli %s\n" if name == "codex" else "%s (Claude Code)\n") % self.system[name], ""
        if argv[0] == self.path(name) and name in self.installed:
            version = self.installed[name]
            if argv[1:] == ["--version"]:
                if version in self.silent:
                    return 139, "", "Segmentation fault"
                return 0, ("codex-cli %s\n" if name == "codex" else "%s (Claude Code)\n") % version, ""
            if argv[1:] == ["--help"]:
                return (1, "", "Error: cannot start") if version in self.bad else (0, HELP, "")
        return 1, "", "unknown command"

    def models(self, exe):
        """codex app-server model/list, as Lifecycle reads it."""
        if self.installed["codex"] in self.bad:
            return None, "codex app-server did not answer model/list in 20 seconds"
        return OPTIONS, None

    def shell(self, script, timeout, cwd):
        self.scripts.append((script, timeout, cwd))
        self.could_start.append(can_start(self.lc))
        name = "claude" if "claude" in script else "codex"
        chosen = re.search(r"(?:--release|bash -s) '?([0-9][0-9A-Za-z.-]*)", script)
        if chosen:                                  # runtime_install: the previous version back, or a first one
            if self.rollback_fails:
                return 1, "", "curl: (6) Could not resolve host: claude.ai"
            self.installed[name] = chosen.group(1)
            if not os.path.exists(self.path(name)):
                self.put(name, BINARY)
        elif self.install_fails:
            return 1, "", "curl: (6) Could not resolve host: chatgpt.com"
        else:                                       # runtime_update: the vendor's newest
            self.installed[name] = self.newest[name]
        return 0, "installed\n", ""


def can_start(lc):
    """A session start from another thread, as the helper's event loop makes it."""
    started = []

    def start():
        try:
            with lc.session_start():
                started.append(True)
        except Updating:
            started.append(False)
    t = threading.Thread(target=start)
    t.start()
    t.join()
    return started[0]


class RuntimeUpdates(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="fleet-runtime-update-")
        self.addCleanup(shutil.rmtree, self.home, ignore_errors=True)
        self.machine = Machine(self.home)
        self.now, self.mono = 1761130000.0, 50000.0     # the wall clock and the monotonic clock, apart
        self.busy = self.in_use = False
        self.posts, self.said = [], []

    def make(self, **kw):
        def post(payload):
            self.posts.append(payload)
            return 200, {"ok": True}
        lc = Lifecycle("/kit", "alpha", {"role": "worker", "runtime": "claude"}, post, busy=lambda: self.busy,
                       run=self.machine, clock=lambda: self.now, monotonic=lambda: self.mono, platform_name="linux",
                       home=self.home, models=self.machine.models, which=self.machine.which,
                       **dict({"runtimes_busy": lambda: self.in_use, "say": self.said.append}, **kw))
        self.machine.lc = lc
        return lc

    def round(self, lc):
        """One tick of the helper's status thread, and the round of updates that it started, to its end."""
        lc.tick()
        if lc.runtime_round:
            lc.runtime_round.join(10)
            self.assertFalse(lc.runtime_round.is_alive())

    def outcome(self, lc, name):
        return lc.runtime_updates()["runtimes"][name]

    def test_a_newer_version_is_installed_with_the_vendors_own_update_and_checked(self):
        lc = self.make()
        self.round(lc)
        self.assertEqual(self.machine.installed, {"claude": "2.1.308", "codex": "0.163.0"})
        # Exactly the vendors' own updates, as this user, from its home, with a time limit, and nothing else.
        self.assertEqual(self.machine.scripts, [
            ('mkdir -p "$HOME/.local/bin" && curl -fsSL https://chatgpt.com/codex/install.sh | '
             'CODEX_INSTALLER_USE_RELEASES_OPENAI_COM=false CODEX_NON_INTERACTIVE=1 sh -s --',
             RUNTIME_INSTALL_WAIT, self.home),
            ('mkdir -p "$HOME/.local/bin" && "$HOME/.local/bin/claude" update', RUNTIME_INSTALL_WAIT, self.home)])
        # No session started while an installer ran, and one can start once the round is over.
        self.assertEqual(self.machine.could_start, [False, False])
        self.assertTrue(can_start(lc))
        self.assertEqual(self.outcome(lc, "claude"), {
            "result": "updated", "at": self.now, "detail": "Updated from 2.1.301 to 2.1.308, which passed its check."})
        self.assertEqual(self.outcome(lc, "codex")["detail"],
                         "Updated from 0.160.0 to 0.163.0, which passed its check.")
        self.assertIn("runtime update of Claude Code (updated): Updated from 2.1.301 to 2.1.308, which passed its "
                      "check.", self.said)
        # The round ends with a report: the hub, and the owner's app, have the new versions at once. The report's
        # own `update` is still the Fleet update's, which a runtime's outcome must not take the place of.
        last = self.posts[-1]["runtimes"]
        self.assertEqual((last["claude"]["version"], last["claude"]["update"]["result"]),
                         ("2.1.308 (Claude Code)", "updated"))
        self.assertEqual((last["codex"]["version"], last["codex"]["update"]["result"]),
                         ("codex-cli 0.163.0", "updated"))
        self.assertEqual(self.posts[-1]["update"], {"state": None, "detail": None})

    def test_a_version_that_fails_its_check_gives_way_to_the_one_before(self):
        self.machine.newest = {"claude": "2.1.309", "codex": "0.164.0"}
        self.machine.bad, self.machine.silent = {"2.1.309"}, {"0.164.0"}
        lc = self.make()
        self.round(lc)
        self.assertEqual(self.machine.installed, {"claude": "2.1.301", "codex": "0.160.0"})
        rollbacks = [s for s, _, _ in self.machine.scripts if "--release" in s or "bash -s" in s]
        self.assertEqual(rollbacks, ['mkdir -p "$HOME/.local/bin" && ' + onboard.runtime_install("codex", "0.160.0"),
                                     'mkdir -p "$HOME/.local/bin" && ' + onboard.runtime_install("claude", "2.1.301")])
        self.assertEqual(self.outcome(lc, "claude")["result"], "rolled_back")
        self.assertEqual(self.outcome(lc, "claude")["detail"], "2.1.309 failed its check (claude --help did not "
                                                               "answer), so 2.1.301 is installed again.")
        self.assertEqual(self.outcome(lc, "codex")["detail"], "The new version failed its check (codex --version "
                                                              "answers no version), so 0.160.0 is installed again.")
        self.assertEqual(self.posts[-1]["runtimes"]["claude"]["version"], "2.1.301 (Claude Code)")

        # A previous version that does not come back is said as it is, with what the owner can do.
        self.now, self.mono = self.now + RUNTIME_UPDATE_EVERY, self.mono + RUNTIME_UPDATE_EVERY
        self.machine.rollback_fails = True
        self.round(lc)
        self.assertEqual(self.outcome(lc, "claude"), {
            "result": "failed", "at": self.now,
            "detail": "2.1.309 failed its check (claude --help did not answer), and 2.1.301 did not come back "
                      "(curl: (6) Could not resolve host: claude.ai). Install 2.1.301 again on this machine."})

    def test_no_update_while_a_session_may_use_a_runtime(self):
        self.busy = True                    # a task window of this agent, a check or a login job
        lc = self.make()
        self.round(lc)
        self.busy, self.in_use = False, True    # a turn in a standing window, or any session of this user
        self.round(lc)
        self.in_use = False
        with lc.lock:
            lc.state = "waiting_idle"       # a Fleet update waits: it goes first, and restarts the helper anyway
        lc.start_runtime_updates()
        self.assertEqual((self.machine.scripts, lc.runtime_round), ([], None))
        self.assertTrue(can_start(lc))      # the idle check took the gate and gave it back
        with lc.lock:
            lc.state = None
        self.round(lc)
        self.assertEqual(len(self.machine.scripts), 2)
        # A Lifecycle without the idle check, the server service's reading of another user, updates nothing.
        self.machine.scripts.clear()
        self.now, self.mono = self.now + 2 * RUNTIME_UPDATE_EVERY, self.mono + 2 * RUNTIME_UPDATE_EVERY
        self.round(self.make(runtimes_busy=None))
        self.assertEqual(self.machine.scripts, [])

    def test_one_round_in_six_hours_for_the_user_also_across_a_restart(self):
        lc = self.make()
        self.round(lc)
        self.assertEqual(len(self.machine.scripts), 2)
        self.now, self.mono = self.now + 3600, self.mono + 3600
        self.round(lc)
        self.round(self.make())         # the helper restarted, as it does with every Fleet update
        self.assertEqual(len(self.machine.scripts), 2)
        self.now, self.mono = self.now + RUNTIME_UPDATE_EVERY - 3600, self.mono + RUNTIME_UPDATE_EVERY - 3600
        lc = self.make()
        self.round(lc)
        self.assertEqual(len(self.machine.scripts), 4)
        self.assertEqual(self.outcome(lc, "claude"), {"result": "current", "at": self.now,
                                                      "detail": "2.1.308 stays: the vendor gives no newer version."})
        self.assertEqual(lc.runtime_updates()["at"], self.now)
        # A time ahead of the clock, after the clock was set back, does not stop the updates for good.
        lc.save_runtime_updates({"at": self.now + 86400, "runtimes": {}})
        self.round(lc)                  # this process's own round was a moment ago
        self.assertEqual(len(self.machine.scripts), 4)
        self.round(self.make())
        self.assertEqual(len(self.machine.scripts), 6)

    def test_the_installed_version_never_goes_down(self):
        self.machine.newest["codex"] = "0.159.0"        # the vendor's newest is older than the one installed
        self.machine.newest["claude"] = "2.1.301"       # and Claude Code's own update has nothing newer
        lc = self.make()
        self.round(lc)
        self.assertEqual(self.machine.installed, {"claude": "2.1.301", "codex": "0.160.0"})
        self.assertEqual(self.outcome(lc, "codex"), {
            "result": "rolled_back", "at": self.now,
            "detail": "0.159.0 failed its check (it is older than 0.160.0), so 0.160.0 is installed again."})
        self.assertEqual(self.outcome(lc, "claude")["result"], "current")
        self.assertFalse(any("bash -s" in s for s, _, _ in self.machine.scripts))      # nothing to put back

    def test_an_update_that_does_not_run_leaves_the_installed_version(self):
        self.machine.install_fails = True
        lc = self.make()
        self.round(lc)
        self.assertEqual(self.machine.installed, {"claude": "2.1.301", "codex": "0.160.0"})
        self.assertEqual(self.outcome(lc, "codex")["detail"], "The update did not run (curl: (6) Could not resolve "
                                                              "host: chatgpt.com); 0.160.0 stays and passes its check.")
        self.assertEqual(self.outcome(lc, "codex")["result"], "failed")
        self.assertEqual(len(self.machine.scripts), 2)                  # no install of the old version over itself

    def test_only_the_vendors_own_installation_that_works_now_is_updated(self):
        # The owner's own launcher in ~/.local/bin, which reads a key from the Keychain and then runs Homebrew's codex.
        self.machine.put("codex", b'#!/bin/bash\nexport OPENAI_API_KEY="$(security find-generic-password -w)"\n'
                                  b'exec /opt/homebrew/bin/codex "$@"\n')
        lc = self.make()
        self.round(lc)
        self.assertEqual(self.outcome(lc, "codex"), {
            "result": "skipped", "at": self.now,
            "detail": f"{self.machine.path('codex')} is a script and not the vendor's program, so it stays as it is."})
        self.assertEqual([s for s, _, _ in self.machine.scripts if "codex" in s], [])

        # Another installer's runtime, an owner who turned Claude Code's updates off, and a version that does not
        # pass the check now (Codex signed out), each stay as they are, and no command runs for them.
        self.machine.put("codex", BINARY)
        self.machine.bad = {"0.160.0"}
        os.makedirs(os.path.join(self.home, ".claude"))
        with open(os.path.join(self.home, ".claude", "settings.json"), "w") as f:
            f.write('{"env": {"DISABLE_AUTOUPDATER": "1"}}')
        self.machine.scripts.clear()
        self.now, self.mono = self.now + RUNTIME_UPDATE_EVERY, self.mono + RUNTIME_UPDATE_EVERY
        self.round(lc)
        self.assertEqual(self.machine.scripts, [])
        self.assertEqual(self.outcome(lc, "claude")["detail"], "DISABLE_AUTOUPDATER in ~/.claude/settings.json turns "
                                                               "its updates off, so it stays as it is.")
        self.assertEqual(self.outcome(lc, "codex")["detail"],
                         "The installed 0.160.0 does not pass the check now (codex app-server did not answer "
                         "model/list in 20 seconds), so no new version is tried.")
        homebrew = Lifecycle("/kit", "alpha", {"runtime": "claude"}, None, lambda: False, run=self.machine,
                             home=self.home, which=lambda name: "/opt/homebrew/bin/" + name)
        self.assertEqual(homebrew.update_runtime("claude")["detail"],
                         "/opt/homebrew/bin/claude is not the vendor's installation in ~/.local/bin, so it stays as "
                         "it is.")
        os.remove(self.machine.path("codex"))
        self.assertIsNone(lc.update_runtime("codex"))       # not installed: nothing to say about it

    def test_a_system_installation_gives_way_to_the_vendors_own_for_an_agent_user(self):
        """A runtime that was on the machine before Founderizer made the agent's install skip the vendor's installer,
        so it never got an update: the owner's own hub ran Claude Code 2.1.285 from /usr/bin on 22 October 2026."""
        os.remove(self.machine.path("claude"))
        del self.machine.installed["claude"]
        self.machine.system["claude"] = "2.1.285"
        lc = self.make()
        self.round(lc)
        pin = onboard.RUNTIME_PINS["claude"]
        self.assertEqual([s for s, _, _ in self.machine.scripts if "claude" in s],
                         ['mkdir -p "$HOME/.local/bin" && ' + onboard.runtime_install("claude", pin),
                          'mkdir -p "$HOME/.local/bin" && "$HOME/.local/bin/claude" update'])
        self.assertEqual(self.machine.installed["claude"], "2.1.308")
        self.assertEqual(self.outcome(lc, "claude")["detail"], f"Updated from {pin} to 2.1.308, which passed its check.")
        self.assertEqual(self.machine.system, {"claude": "2.1.285"})          # the system's own stays untouched

    def test_a_vendors_installation_that_fails_its_check_leaves_the_system_one_in_place(self):
        os.remove(self.machine.path("claude"))
        del self.machine.installed["claude"]
        self.machine.system["claude"] = "2.1.285"
        self.machine.bad.add(onboard.RUNTIME_PINS["claude"])
        lc = self.make()
        self.round(lc)
        self.assertFalse(os.path.exists(self.machine.path("claude")))       # /usr/bin/claude answers again
        self.assertEqual(self.outcome(lc, "claude")["result"], "skipped")
        self.assertIn("so /usr/bin/claude stays", self.outcome(lc, "claude")["detail"])
        # A Mac keeps its installations, and so does Homebrew: only an agent's own Linux user takes the vendor's.
        mac = Lifecycle("/kit", "alpha", {"runtime": "claude"}, None, lambda: False, run=self.machine,
                        home=self.home, which=self.machine.which, platform_name="darwin")
        self.assertEqual(mac.update_runtime("claude")["detail"],
                         "/usr/bin/claude is not the vendor's installation in ~/.local/bin, so it stays as it is.")

    def test_two_helpers_of_one_user_never_update_at_the_same_time(self):
        """A Mac keeps one user, and so one ~/.local/bin, for all of its agents, and each agent has a helper."""
        lc = self.make()
        os.makedirs(os.path.join(self.home, ".fleet"), exist_ok=True)
        with open(os.path.join(self.home, ".fleet", lifecycle.RUNTIME_UPDATES_LOCK), "a") as other:
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)      # the other helper's round runs
            self.round(lc)
            self.assertEqual(self.machine.scripts, [])
            self.assertTrue(can_start(lc))
        self.round(lc)                  # this process tries again in six hours, and not at every tick
        self.assertEqual(self.machine.scripts, [])
        self.round(self.make())         # the next helper of this user, with the lock free
        self.assertEqual(len(self.machine.scripts), 2)

    def test_the_hub_keeps_the_outcome_and_drops_one_of_another_shape(self):
        update = {"result": "rolled_back", "at": 1761130000.5, "detail": " 2.1.309 failed its check. "}
        status = hub.validate_status({"runtimes": {
            "claude": {"version": "2.1.301 (Claude Code)", "signed_in": True, "update": update},
            "codex": {"version": "codex-cli 0.160.0", "signed_in": True,
                      "update": {"result": "exploded", "at": 1, "detail": "x"}}}})
        self.assertEqual(status["runtimes"], {
            "claude": {"version": "2.1.301 (Claude Code)", "signed_in": True,
                       "update": {"result": "rolled_back", "at": 1761130000.5, "detail": "2.1.309 failed its check."}},
            "codex": {"version": "codex-cli 0.160.0", "signed_in": True}})       # as from a helper before this

    def test_the_helper_loads_onboard_now_so_a_change_of_it_is_an_update(self):
        """The installers are onboard.py's, and the helper runs them: a release that changes only that file must
        restart the helpers like any other code, or they would run the old install lines."""
        self.assertIsNone(lifecycle.OWNER_ONLY.search("onboard.py"))
        self.assertIsNone(hub.OWNER_ONLY.search("onboard.py"))
        self.assertTrue(lifecycle.OWNER_ONLY.search("pilot.py") and hub.OWNER_ONLY.search("pilot.py"))


SOCKET = tmux_socket("fleet-runtime-update-test")


@unittest.skipUnless(shutil.which("tmux"), "tmux is not installed")
class EveryFleetSessionOfTheUser(unittest.TestCase):
    """Helper.runtimes_busy, on real tmux: a session of any agent of this user may use the runtime."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="fleet-runtime-busy-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.addCleanup(subprocess.run, ["tmux", "-S", SOCKET, "kill-server"], capture_output=True)
        real = fleet.tmux
        for p in (patch.object(fleet, "tmux", lambda *args, **kw: real("-S", SOCKET, *args, **kw)),
                  patch.object(fleet, "HOME", os.path.join(self.tmp, ".fleet")),
                  patch.object(fleet, "HUB", "http://127.0.0.1:9"),          # never a real hub
                  patch.object(fleet, "http", return_value=(200, {}))):
            p.start()
            self.addCleanup(p.stop)
        self.helper = fleet.Helper("alpha", {"role": "worker", "runtime": "claude", "can": ["shell"],
                                             "start": "claude --permission-mode dontAsk {settings} {prompt}"})

    def shows(self, target, text):
        for _ in range(50):
            if text in fleet.tmux("capture-pane", "-p", "-t", target).stdout:
                return True
            time.sleep(0.1)
        return False

    def test_a_task_a_turn_or_a_sign_in_of_any_agent_of_the_user_holds_the_update(self):
        t = fleet.tmux
        t("new-session", "-d", "-s", "fleet-alpha", "-n", "home", "sleep 120", check=True)
        t("new-window", "-t", "fleet-alpha", "-n", "owner-chat", "sleep 120", check=True)
        t("new-session", "-d", "-s", "work", "-n", "T-1", "sleep 120", check=True)     # the owner's own, not Fleet's
        self.assertFalse(self.helper.runtimes_busy())

        t("new-window", "-t", "fleet-alpha", "-n", "C-7",
          "sh -c 'echo \"* Working (4s - esc to interrupt)\"; sleep 120'", check=True)
        self.assertTrue(self.shows("fleet-alpha:=C-7", "esc to interrupt"))
        self.assertTrue(self.helper.runtimes_busy())                    # a turn runs in a conversation window
        t("kill-window", "-t", "fleet-alpha:=C-7", check=True)
        self.assertFalse(self.helper.runtimes_busy())

        t("new-session", "-d", "-s", "fleet-beta", "-n", "T-4", "sleep 120", check=True)
        self.assertTrue(self.helper.runtimes_busy())                    # a task of another agent of this user
        t("kill-session", "-t", "fleet-beta", check=True)
        t("new-session", "-d", "-s", "fleet-login-alpha", "-n", "login", "sleep 120", check=True)
        self.assertTrue(self.helper.runtimes_busy())                    # a sign-in runs the runtime
        t("kill-session", "-t", "fleet-login-alpha", check=True)
        self.assertFalse(self.helper.runtimes_busy())


if __name__ == "__main__":
    unittest.main()

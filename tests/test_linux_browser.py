"""The agents' browser on a Linux server, the helper's side (build plan 04, S2): `Helper.sweep_browser`, which stops an
agent's browser and screen-sharing units where no open task holds them."""
import contextlib
import io
import subprocess
import types
import unittest
from unittest.mock import patch

import fleet
from leftovers import scratch_home

STOPS = [["systemctl", "--user", "--no-block", "stop", "fleet_browser.service"],
         ["systemctl", "--user", "--no-block", "stop", "fleet_vnc.service"]]


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


class SweepBrowser(unittest.TestCase):
    """S2a: a helper that started again, a task that ended while the helper did not run or under a release that took
    the browser back leaves no Chrome running for long; a browser that an open task holds stays."""

    def sweep(self, open_tasks, windows=(), worker=True, at=None, platform="linux", own=True, answer=0, now=5000.0):
        """One call on a stand-in helper. `windows` are tmux's lines "<name>\\t<needs>", given only to the right
        list-windows; None is a tmux that does not answer, "gone" a session that is not there. `answer` is systemd's
        exit code for each stop. Returns (the stops asked for, when the helper counts its last sweep)."""
        helper = types.SimpleNamespace(open_tasks=open_tasks, worker=worker, browser_at=at, session="fleet-ivy",
                                       own_user=lambda: own)

        def tmux(*args):
            if args != ("list-windows", "-t", "=fleet-ivy:", "-F", "#{window_name}\t#{@fleet_needs}"):
                return subprocess.CompletedProcess(args, 0, "T-1\tnone\n", "")      # another list: not this one
            if windows is None:
                return subprocess.CompletedProcess(args, 1, "", "server exited unexpectedly")
            if windows == "gone":
                return subprocess.CompletedProcess(args, 1, "", "can't find session: fleet-ivy")
            return subprocess.CompletedProcess(args, 0, "".join(w + "\n" for w in windows), "")
        stops = []
        with patch.object(fleet, "tmux", tmux), patch.object(fleet.sys, "platform", platform), \
                patch.object(fleet.time, "monotonic", lambda: now), contextlib.redirect_stdout(io.StringIO()):
            fleet.Helper.sweep_browser(helper, stop=lambda argv, **_: stops.append(argv) or
                                       subprocess.CompletedProcess(argv, answer, "", "Failed to connect to bus"))
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

    def test_nothing_is_decided_on_what_is_not_known(self):
        # Before the first poll, a worker's hub that names no open task, a tmux that does not answer, a Mac (whose
        # browser is the owner's Chrome), and an agent that shares its OS user with others.
        for kwargs in (dict(open_tasks=False), dict(open_tasks=None), dict(open_tasks=["T-1"], windows=None),
                       dict(open_tasks=["T-1"], platform="darwin"), dict(open_tasks=["T-1"], own=False)):
            self.assertEqual(self.sweep(**kwargs), ([], None), kwargs)


if __name__ == "__main__":
    unittest.main()

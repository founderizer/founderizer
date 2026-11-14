"""selftest.py starts hubs of its own, and a folder for their records. However its run ends, nothing of it outlives it
(AGENTS.md: a test stops the servers and removes the folders that it made). On 11 November 2026 ten hubs of ended
runs still served on the owner's Mac, the oldest for eight days: one run had ended with "the hub did not start", and a
caller that gives up on a run kills it with SIGKILL at its time-out, which no cleanup inside the run survives.

    python3 -m unittest -v test_selftest_cleanup

Each test starts selftest.py, waits until its first hub has its records, ends the run one way, and then finds no
process that names the run's folder (its hubs, its guard) and no folder. A run takes a few seconds this way: the
checks of selftest.py itself do not run.
"""
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

KIT = os.path.dirname(os.path.abspath(__file__))
WAIT = 120          # seconds for a run to start its first hub, on a Mac where every thread runs its tests
GONE_WAIT = 60      # seconds for what an ended run leaves to go


def naming(text):
    """The processes whose command line names `text`."""
    listed = subprocess.run(["ps", "-A", "-ww", "-o", "pid=,command="], capture_output=True, text=True).stdout
    return [line.strip() for line in listed.splitlines() if text in line]


class AnEndedRun(unittest.TestCase):

    def setUp(self):
        # TMPDIR of the run: its folder is made in this test's own, so that a run of another thread on this Mac is
        # neither found nor touched.
        self.tmp = tempfile.mkdtemp(prefix="selftest-cleanup-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def ended(self, number, hold_the_guard=False):
        """A run that had its first hub, ended with signal `number`: (its hubs and whether its folder is there, at the
        moment the run has ended), and (the processes that name its folder, and the folders, once that is over).

        With hold_the_guard, the run's guard is stopped (SIGSTOP) until the run has ended, so that what is gone at
        that moment is the run's own doing: its hubs stop themselves and the guard removes the folder a few
        milliseconds after the run ends, which no check could tell apart from the run's own cleanup."""
        run = subprocess.Popen([sys.executable, os.path.join(KIT, "selftest.py")], cwd=KIT,
                               env=dict(os.environ, TMPDIR=self.tmp), stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def stop():
            if run.poll() is None:
                run.kill()
                run.wait()
        self.addCleanup(stop)
        deadline, records = time.time() + WAIT, None
        while time.time() < deadline and run.poll() is None and not records:
            records = [os.path.join(self.tmp, one, "main.db") for one in os.listdir(self.tmp)
                       if os.path.exists(os.path.join(self.tmp, one, "main.db"))]
            time.sleep(0.1)
        self.assertTrue(records, f"the run started no hub in {WAIT} seconds (it ended with {run.poll()})")
        folder = os.path.dirname(records[0])
        self.assertTrue(naming(records[0]), "the hub of the run is not running, so there is nothing to leave")
        held = []
        if hold_the_guard:
            held = [int(line.split()[0]) for line in naming(folder) if " --guard " in line]
            self.assertEqual(len(held), 1, f"not one guard: {naming(folder)}")
            os.kill(held[0], signal.SIGSTOP)

            def go_on():
                try:
                    os.kill(held.pop(), signal.SIGCONT)
                except (IndexError, ProcessLookupError):
                    pass
            self.addCleanup(go_on)
        os.kill(run.pid, number)
        run.wait(timeout=GONE_WAIT)
        at_its_end = ([line for line in naming(folder) if "hub.py" in line], os.path.exists(folder))
        if held:
            go_on()
        deadline = time.time() + GONE_WAIT
        while time.time() < deadline and (naming(self.tmp) or os.listdir(self.tmp)):
            time.sleep(0.2)
        return at_its_end, (naming(self.tmp), os.listdir(self.tmp))

    def test_a_run_that_its_caller_kills_at_a_time_out_leaves_nothing(self):
        """subprocess.run(timeout=...) in autopublish.py, releases.py, verify.py and test_publish.py. Nothing of the
        run is left to act, so its hubs stop themselves, and its guard removes the folder after them."""
        self.assertEqual(self.ended(signal.SIGKILL)[1], ([], []))

    def test_a_run_that_is_stopped_has_stopped_its_hubs_when_it_ends(self):
        """The same way out as "the hub did not start" and every other early end: SystemExit, then finish()."""
        self.assertEqual(self.ended(signal.SIGTERM, hold_the_guard=True), (([], False), ([], [])))

    def test_a_run_that_a_ctrl_c_ends_has_stopped_its_hubs_when_it_ends(self):
        """KeyboardInterrupt: the way out of an exception, as when a print finds that its reader has gone."""
        self.assertEqual(self.ended(signal.SIGINT, hold_the_guard=True), (([], False), ([], [])))


# What a run's first hub does at its start, before a line of hub.py runs: Python reads sitecustomize.py at each start,
# and the run gives its hubs its own environment. The mark makes it the first hub only.
FIRST_HUB = """import os, sys, time
mark = os.environ.get("SELFTEST_FIRST_HUB")
if mark and os.path.basename(sys.argv[0]) == "hub.py" and not os.path.exists(mark):
    open(mark, "w").close()
    %s
"""
LATE = 12           # seconds before that hub goes on: more than the 80 readings, about 8 seconds, of before


class AHubThatStartsLate(unittest.TestCase):
    """A hub's start makes its database, and on a slow disk that took 8 to 9 seconds (a test server of 13 November
    2026). Until 14 November 2026 the run gave a hub 80 readings, a tenth of a second apart, and then said "the hub
    did not start" over a server that was in order. The wait now ends at the hub's answer or at the end of the hub's
    process."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="selftest-late-hub-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def run_with(self, first_hub):
        """A run whose first hub does `first_hub` at its start: what the run printed until its first check or its end,
        and its status, or None when it still ran then. The run is ended here, and it leaves nothing."""
        site, out = os.path.join(self.tmp, "site"), os.path.join(self.tmp, "out")
        os.mkdir(site)
        with open(os.path.join(site, "sitecustomize.py"), "w") as f:
            f.write(FIRST_HUB % first_hub)
        with open(out, "w") as printed:
            run = subprocess.Popen([sys.executable, os.path.join(KIT, "selftest.py"), "-v"], cwd=KIT,
                                   env=dict(os.environ, TMPDIR=self.tmp, PYTHONPATH=site, PYTHONUNBUFFERED="1",
                                            SELFTEST_FIRST_HUB=os.path.join(self.tmp, "first-hub")),
                                   stdin=subprocess.DEVNULL, stdout=printed, stderr=subprocess.DEVNULL)

        def stop():
            if run.poll() is None:
                run.kill()
                run.wait()
        self.addCleanup(stop)
        deadline = time.time() + WAIT + LATE
        while time.time() < deadline and run.poll() is None and not os.path.getsize(out):
            time.sleep(0.1)
        for _ in range(100):            # a run that printed why it stops ends a moment after its line
            if run.poll() is not None:
                break
            time.sleep(0.1)
        status = run.poll()
        if status is None:
            run.send_signal(signal.SIGTERM)
            run.wait(timeout=GONE_WAIT)
        deadline = time.time() + GONE_WAIT
        while time.time() < deadline and naming(self.tmp):
            time.sleep(0.1)
        with open(out) as printed:
            return printed.read(), status

    def test_a_hub_that_listens_after_twelve_seconds_is_waited_for(self):
        said, status = self.run_with(f"time.sleep({LATE})")
        self.assertNotIn("the hub did not start", said)
        self.assertEqual(status, None, said)                    # the run went on to its checks
        self.assertTrue(said.startswith(("PASS ", "FAIL ")), said)
        self.assertEqual(naming(self.tmp), [])

    def test_a_hub_whose_process_ended_stops_the_run_at_once_with_its_status(self):
        said, status = self.run_with("os._exit(3)")
        self.assertEqual((said, status), ("the hub did not start: its process ended with status 3\n", 1))
        self.assertEqual(naming(self.tmp), [])


if __name__ == "__main__":
    unittest.main()

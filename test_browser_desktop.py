"""Owner live view of browser tasks on a Mac that can show its screen. In-process hub; no capture or AI calls."""
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import desktop
import fleet
import hub
from test_ui_api import OwnerAPI


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(BrowserLease(name) for name in BrowserLease.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(BrowserPublisher))
    return suite


class BrowserLease(OwnerAPI):
    def task(self, owner, needs):
        hub.DESKTOP = desktop.Frames()
        hub.TEAM["addresses"]["studio"] = hub.TEAM["addresses"]["vps"] = "127.0.0.1"
        hub.TEAM["agents"]["studio"] = dict(role="worker", runtime="claude", machine="studio", can=["browser", "screen"])
        hub.TEAM["agents"]["vps"] = dict(role="worker", runtime="codex", machine="vps", can=["shell"])
        return hub.ins("INSERT INTO tasks(title,owner,state,needs,attempt) VALUES('Watch',?,'working',?,1)", (owner, needs))

    def view(self, tid):
        return self.request(f"/ui/tasks/{tid}/desktop?db=test-generation&attempt=1")

    def test_a_browser_task_on_a_screen_mac_can_be_watched(self):
        tid = self.task("studio", "browser")
        code, data = self.view(tid)
        self.assertEqual((code, data["status"]), (200, "waiting"))
        self.assertIn("browser_desktop", self.request()[1]["ui_features"])

    def test_no_view_without_screen_capability_or_for_plain_tasks(self):
        self.assertEqual(self.view(self.task("vps", "browser"))[0], 409)
        self.assertEqual(self.view(self.task("studio", "none"))[0], 409)


class BrowserPublisher(unittest.TestCase):
    def helper(self, windows):
        helper = fleet.Helper("studio", dict(role="worker", runtime="claude", can=["browser", "screen"]))
        listing = subprocess.CompletedProcess([], 0, stdout="".join(f"{w}\n" for w in windows), stderr="")
        return helper, patch("fleet.tmux", return_value=listing)

    def test_one_publisher_per_browser_task_attempt(self):
        helper, tmux = self.helper(["home\t\t", "T-4\tdb:1\tbrowser", "T-5\tdb:1\t", "owner-chat\tdb:1\t"])
        made = MagicMock()
        made.return_value.thread.is_alive.return_value = True
        with tmux, patch("fleet.Publisher", made), patch.object(fleet.sys, "platform", "darwin"):
            helper.sweep_desktop()
            helper.sweep_desktop()
        made.assert_called_once_with("studio", "T-4", {"attempt": 1, "generation": "db"}, fleet.http)
        made.return_value.start.assert_called_once()

    def test_a_publisher_that_the_hub_ended_starts_again_only_after_a_line_went_into_its_window(self):
        """A publisher ends by itself only at the hub's 403, 404 or 409 (desktop.Publisher), which a new one gets
        again. Each sweep started a new one, which asked the hub once more. Now a line that went into its window since
        its start, as the message that resumes a held task, starts it again; a new attempt is a new publisher."""
        helper, tmux = self.helper(["T-4\tdb:1\tbrowser"])
        made = MagicMock()
        made.return_value.thread.is_alive.return_value = False     # it ended at the hub's answer
        made.return_value.ended = 409
        with tmux, patch("fleet.Publisher", made), patch.object(fleet.sys, "platform", "darwin"):
            helper.sweep_desktop()
            helper.sweep_desktop()
            self.assertEqual(made.call_count, 1)
            helper.typed_at["T-4"] = fleet.time.monotonic()         # a line went into its window since
            helper.sweep_desktop()
            helper.sweep_desktop()
            self.assertEqual(made.call_count, 2)
            made.return_value.ended = None          # one that ended for another reason starts again at once
            helper.sweep_desktop()
            self.assertEqual(made.call_count, 3)
        listing = subprocess.CompletedProcess([], 0, stdout="T-4\tdb:2\tbrowser\n", stderr="")
        made.return_value.ended = 409
        with patch("fleet.tmux", return_value=listing), patch("fleet.Publisher", made), \
                patch.object(fleet.sys, "platform", "darwin"):
            helper.sweep_desktop()
        made.assert_called_with("studio", "T-4", {"attempt": 2, "generation": "db"}, fleet.http)
        self.assertEqual(made.call_count, 4)

    def test_a_publisher_ends_by_itself_only_at_the_hub_s_refusal(self):
        """desktop.Publisher.ended says why it ended, so that the helper starts again one that ended for another
        reason."""
        answers = [(200, {"watching": False}), (409, {"error": "an old attempt"})]
        publisher = desktop.Publisher("studio", "T-4", {"attempt": 1, "generation": "db"},
                                      lambda method, path, data=None, timeout=None: answers.pop(0))
        publisher.stop.wait = lambda seconds: None
        publisher.run()
        self.assertEqual((publisher.ended, answers), (409, []))

    def test_a_closed_window_stops_its_publisher(self):
        helper, tmux = self.helper(["T-4\tdb:1\tbrowser"])
        made = MagicMock()
        with tmux, patch("fleet.Publisher", made), patch.object(fleet.sys, "platform", "darwin"):
            helper.sweep_desktop()
        helper2_listing = subprocess.CompletedProcess([], 0, stdout="home\t\t\n", stderr="")
        with patch("fleet.tmux", return_value=helper2_listing), patch.object(fleet.sys, "platform", "darwin"):
            helper.sweep_desktop()
        made.return_value.close.assert_called_once()

    def test_no_publisher_on_linux_or_without_a_desktop(self):
        helper, tmux = self.helper(["T-4\tdb:1\tbrowser"])
        made = MagicMock()
        with tmux, patch("fleet.Publisher", made), patch.object(fleet.sys, "platform", "linux"):
            helper.sweep_desktop()
        helper.conf = dict(role="worker", runtime="claude", can=["shell", "web"])
        with tmux, patch("fleet.Publisher", made), patch.object(fleet.sys, "platform", "darwin"):
            helper.sweep_desktop()
        made.assert_not_called()
        helper.conf = dict(role="worker", runtime="claude", can=["browser"])    # a Mac set up for Claude alone
        with tmux, patch("fleet.Publisher", made), patch.object(fleet.sys, "platform", "darwin"):
            helper.sweep_desktop()
        made.assert_called_once()


if __name__ == "__main__":
    unittest.main()

"""Owner live view of browser tasks on a Mac that can show its screen; and the places of the agents' browsers on a Linux
server (build plan 04, S3). In-process hub; no capture or AI calls."""
import json
import subprocess
import unittest
from unittest.mock import MagicMock, patch

import desktop
import fleet
from leftovers import scratch_home
import hub
from test_ui_api import OwnerAPI


def setUpModule():
    scratch_home()      # no test of this file reads or writes the real ~/.fleet (leftovers.scratch_home)


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(BrowserLease(name) for name in BrowserLease.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(BrowserPublisher))
    suite.addTests(LinuxPlaces(name) for name in LinuxPlaces.__dict__ if name.startswith("test_"))
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



MIB = 1 << 20
CX23 = {"memory_max": 3247 * MIB, "swap_max": None, "swap_total": 1910 * MIB, "swap_current": 0, "swap_peak": 0,
        "oom": 0, "swap_fail": 0, "full_us": 0}      # user.slice of a cx23 with part 1's limit and swap (probe 2)
ONE_PLACE = dict(CX23, memory_max=5800 * MIB)      # a server whose room gives its two agents with a shell one place


class LinuxPlaces(OwnerAPI):
    """Build plan 04, S3 (D6, D9, D10): an agent on a Linux server runs its browser tasks in a Chrome of its own, one at
    a time, while its server has a free place; a place is a Chrome that runs at one time, from the room of user.slice.
    A refused requester hears when one is free, and a wait gives its place back."""

    def setUp(self):
        super().setUp()
        hub.TEAM["addresses"].update(box="127.0.0.3")
        hub.TEAM["hub"] = {"machine": "hub", "port": 8765}
        hub.TEAM["servers"] = {"box": {"kind": "linux", "user": "fleet"}}
        for name in ("ivy", "kai"):
            hub.TEAM["agents"][name] = {"role": "worker", "runtime": "claude", "machine": "box",
                                        "can": ["shell", "web", "browser"]}
            hub.know(name)
        hub.know("manager")
        self.room(ONE_PLACE)

    def room(self, room, boot="b1", state="ready"):
        """The server service's reading of box, with the room of its user.slice."""
        users = {n: {"user": f"fleet-{n}", "uid": 1001 + i} for i, n in enumerate(("ivy", "kai", "gus"))}
        data = {"os": {"name": "Ubuntu 24.04.3 LTS", "kernel": "6.8", "boot": boot}, "room": room, "agents": users,
                "browser": {"state": state, "ports": [{"user": u["user"], "devtools": 9301 + i, "screen": 5911 + i}
                                                       for i, u in enumerate(users.values())]}}
        hub.q("INSERT INTO server_status(server,data,reported) VALUES(?,?,?) ON CONFLICT(server) DO UPDATE SET "
              "data=excluded.data, reported=excluded.reported", ("box", json.dumps(data), hub.now()))
        return data

    def task(self, owner, requester="manager"):
        """A browser task through create_task: its T-<id>, or the refusal's words."""
        try:
            hub.t_create_task(requester, {"owner": owner, "title": "Read the page", "done_when": "read",
                                          "needs": "browser"})
        except hub.ToolError as e:
            return str(e)
        return hub.q1("SELECT MAX(id) id FROM tasks")["id"]

    def closed(self, tid, t0=None):
        """Its end, confirmed: the helper acknowledged its stop event and then reported its windows without it."""
        t0 = t0 or hub.now()
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (tid,))
        owner = hub.q1("SELECT owner FROM tasks WHERE id=?", (tid,))["owner"]
        hub.q("INSERT INTO events(agent,kind,task,text,created,extra,helper_ack) VALUES(?,?,?,?,?,?,?)",
              (owner, "stop", tid, "stop", t0, "{}", t0))
        hub.q("UPDATE agents SET alive='', alive_ts=? WHERE name=?", (t0 + 1, owner))

    def said(self, agent):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent=? AND kind='say' ORDER BY id", (agent,))]

    def test_places_come_from_the_room_of_the_slice_and_every_agent_s_need(self):
        """D6, with probe 2's cx23: 1 place with one agent with a shell, none with two (S4 of 19 November 2026: a lead
        and an agent without a shell stalled worker-1 beside a browser), none with three, none without the swap file,
        and none before part 1 put a limit on the slice."""
        self.room(CX23)
        team = json.loads(json.dumps(hub.TEAM))
        self.assertEqual(hub.browser_places("box", team), 0)
        del team["agents"]["kai"]
        self.assertEqual(hub.browser_places("box", team), 1)
        team["agents"]["kai"] = dict(team["agents"]["ivy"])
        team["agents"]["lea"] = dict(team["agents"]["ivy"])
        self.assertEqual(hub.browser_places("box", team), 0)
        del team["agents"]["lea"]
        team["agents"]["kai"]["can"] = ["web"]          # worker-1's team in S4: no place on a cx23
        self.assertEqual(hub.browser_places("box", team), 0)
        self.room(dict(CX23, memory_max=5000 * MIB))    # an agent without a shell needs less, and takes no browser:
        self.assertEqual(hub.browser_places("box", team), 1)        # the formula gives 2, the cap 1
        team["agents"]["kai"]["can"] = ["shell", "web"]
        self.assertEqual(hub.browser_places("box", team), 0)
        self.room(ONE_PLACE)                            # the two agents with a shell: 1 place, which needs its swap
        self.assertEqual(hub.browser_places("box"), 1)
        self.room(dict(ONE_PLACE, swap_total=0))
        self.assertEqual(hub.browser_places("box"), 0)
        self.room(dict(ONE_PLACE, memory_max=None))
        self.assertEqual(hub.browser_places("box"), 0)
        self.room(dict(ONE_PLACE, swap_max=0))          # a limit of the slice's swap counts before the swap file
        self.assertEqual(hub.browser_places("box"), 0)
        self.room(dict(ONE_PLACE, swap_total=0, swap_max=1907 * MIB))  # and only the swap that exists counts
        self.assertEqual(hub.browser_places("box"), 0)

    def test_a_real_shortage_takes_a_place_until_the_next_boot_or_a_change_of_the_limits(self):
        """D6: a new oom of the slice, a new fail of its swap, or more than 5 s of full stall in 300 s takes one place
        for each reading that shows one; a reading of a new boot or of new limits starts again."""
        hub.TEAM["agents"]["kai"]["can"] = ["shell", "browser"]
        t0 = 1_000_000.0
        reading = lambda **room: self.room(dict(dict(CX23, memory_max=7000 * MIB), **room))     # noqa: E731
        seen = lambda r, at: hub.browser_room_seen("box", r, at)        # noqa: E731
        seen(reading(), t0)
        self.assertEqual(hub.browser_places("box"), 2)
        seen(reading(full_us=4_000_000), t0 + 300)      # 4 s of full stall in 300 s: no sign
        self.assertEqual(hub.browser_places("box"), 2)
        seen(reading(full_us=13_000_000), t0 + 1200)    # 9 s more in 900 s: under 15 s, no sign
        self.assertEqual(hub.browser_places("box"), 2)
        seen(reading(full_us=13_000_000, swap_fail=3), t0 + 1500)
        self.assertEqual(hub.browser_places("box"), 1)
        seen(reading(full_us=19_000_000, swap_fail=3), t0 + 1800)       # 6 s in 300 s
        self.assertEqual(hub.browser_places("box"), 0)
        seen(reading(full_us=19_000_000, swap_fail=3, oom=1), t0 + 2100)
        self.assertEqual(hub.browser_places("box"), 0)                   # never fewer than none
        seen(dict(reading(), os={"boot": "b2"}), t0 + 2400)             # it booted: its counters start at 0
        self.assertEqual(hub.browser_places("box"), 2)
        seen(dict(reading(oom=1), os={"boot": "b2"}), t0 + 2700)
        self.assertEqual(hub.browser_places("box"), 1)
        seen(dict(reading(oom=1, memory_max=7100 * MIB), os={"boot": "b2"}), t0 + 3000)    # a new limit
        self.assertEqual(hub.browser_places("box"), 2)

    def test_a_browser_task_takes_its_place_and_the_next_one_hears_when_one_is_free(self):
        first = self.task("ivy")
        self.assertIsInstance(first, int, first)
        self.assertEqual(hub.browser_holders("box"), [first])
        refused = self.task("kai")
        self.assertEqual(refused, f"The desktop of box is busy with T-{first}; wait until it ends. The hub tells you "
                                  f"when a browser place is free there.")
        self.assertIn("busy with another browser or screen task;", hub.browser_refusal("kai", "gone"))  # a run's
        # reason, in the words that the owner's apps know; only the manager sees another task's ID
        self.assertIn(f"busy with T-{first}; wait until it ends.", self.task("ivy"))     # D9: one at a time
        hub.browser_place_sweep(hub.now())
        self.assertEqual(self.said("manager"), [])
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (first,))
        hub.browser_place_sweep(hub.now())          # its session is not confirmed closed yet: it holds its place
        self.assertEqual((hub.browser_holders("box"), self.said("manager")), ([first], []))
        self.closed(first)
        hub.browser_place_sweep(hub.now())
        hub.browser_place_sweep(hub.now())
        free = [s for s in self.said("manager") if "browser place is free" in s]
        self.assertEqual(free, ["[hub] A browser place is free on box now. If you still need the browser task that "
                                "the hub refused for want of one, create it again."])
        self.assertEqual(self.said("ivy"), [])          # a requester that was not refused hears nothing
        self.assertIsInstance(self.task("kai"), int)

    def test_a_wait_gives_its_place_back_and_its_end_takes_a_free_one_or_waits_for_it(self):
        """D10: a usage limit's wait gives the place back when the hub tells the helper to close Chrome; at its end the
        task takes a free place, or waits for one as `place`, and its session hears both once."""
        first = self.task("ivy")
        hub.q("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('ivy',?,?,1)", (hub.now(), hub.now() + 60))
        ref = f"T-{first}"
        self.assertEqual(hub.browser_waits("ivy", closed=set(), alive={ref}), {ref: "limit"})
        self.assertEqual(hub.browser_holders("box"), [first])      # its helper has not closed its Chrome yet
        self.assertEqual(hub.browser_waits("ivy", closed={ref}, alive={ref}), {ref: "limit"})
        self.assertEqual(hub.browser_holders("box"), [])
        second = self.task("kai")
        self.assertIsInstance(second, int, second)
        hub.q("UPDATE agent_limits SET ended=? WHERE agent='ivy'", (hub.now(),))
        self.assertEqual(hub.browser_waits("ivy"), {f"T-{first}": "place"})
        self.assertEqual(hub.browser_waits("ivy"), {f"T-{first}": "place"})
        self.assertIn("closed until a browser place is free there", "".join(self.said("ivy")))
        task = hub.q1("SELECT * FROM tasks WHERE id=?", (first,))
        self.assertEqual(hub.live_reason(task, None), ("place", "a browser place on box"))    # quiet on purpose
        self.assertIn("busy with", self.task("kai"))        # D9 for kai, and a third task finds the place pending
        self.closed(second)
        self.assertEqual(hub.browser_waits("ivy"), {})
        self.assertEqual(hub.browser_holders("box"), [first])
        told = [s for s in self.said("ivy") if "runs again" in s or "closed until" in s]
        self.assertEqual(len(told), 2, told)

    def secret(self, tid, saved=True):
        """A secret request of ivy's task, which the owner answered; `saved`: its reference is saved."""
        spec = {"kind": "login", "site": "example.com", "tasks": [tid], **({"saved": "bws://" + "a" * 36} if saved else {})}
        nid = hub.ins("INSERT INTO needs(id,title,why,todo,raised,by,kind,secret,answer,answered) VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (hub.unused_id("needs"), "Enter a login", "", "", hub.now(), "ivy", "secret", json.dumps(spec),
                       "saved", hub.now()))
        hub.q("UPDATE tasks SET state='input-required', waiting_on=? WHERE id=?", (f"N-{nid}", tid))
        return nid

    def test_a_secret_s_answer_wakes_a_browser_task_only_with_a_free_place(self):
        """D10: a wait for a secret gives its place back; the owner's answer wakes the task only once a place is free,
        and the task takes it in the same transaction. While it waits only for a place it is next in line, and a wait
        for a secret that has not reached the agent keeps no place from anybody."""
        hub.TEAM["agents"]["ivy"]["vault"] = "file"         # the vault reads the answer at once
        first = self.task("ivy")
        nid = self.secret(first, saved=False)
        self.assertEqual(hub.browser_waits("ivy", closed={f"T-{first}"}), {f"T-{first}": "secret"})
        self.assertEqual(hub.browser_holders("box"), [])
        self.assertEqual(hub.browser_pending("box"), [])          # a secret on its way holds no place
        other = self.task("kai")
        self.assertIsInstance(other, int, other)
        spec = json.loads(hub.q1("SELECT secret FROM needs WHERE id=?", (nid,))["secret"])
        hub.q("UPDATE needs SET secret=? WHERE id=?", (json.dumps(dict(spec, saved="bws://" + "a" * 36)), nid))
        hub.secret_wakes()
        self.assertIsNone(json.loads(hub.q1("SELECT secret FROM needs WHERE id=?", (nid,))["secret"]).get("woken"))
        self.assertEqual(hub.browser_pending("box"), [first])     # it waits only for a place now: it is next
        self.closed(other)
        hub.secret_wakes()
        self.assertIsNotNone(json.loads(hub.q1("SELECT secret FROM needs WHERE id=?", (nid,))["secret"]).get("woken"))
        self.assertEqual(hub.browser_holders("box"), [first])

    def test_only_a_linux_server_that_joined_runs_an_agent_s_browser_and_only_its_own_tasks_hold_it(self):
        hub.TEAM["agents"]["gus"] = {"role": "worker", "runtime": "grok", "machine": "box", "can": ["shell", "browser"]}
        self.assertEqual(self.task("gus"), "gus gets no browser on box: a browser on a Linux server runs in a Claude "
                                           "Code or Codex session in this version, and this agent runs on Grok.")
        del hub.TEAM["agents"]["gus"]
        hub.TEAM["agents"]["hal"] = {"role": "worker", "runtime": "claude", "machine": "hub", "can": ["shell", "browser"]}
        hub.TEAM["servers"]["hub"] = {"kind": "linux", "user": "fleet"}
        self.assertIn("hal gets no browser on hub: a browser of an agent runs on a Linux server that joined, and not on "
                      "the hub's own", self.task("hal"))
        self.assertFalse(hub.browser_tabs("ivy"))      # D8: one browser task at a time on Linux
        first = self.task("ivy")
        self.assertIsNone(hub.desktop_busy("kai", "browser"))      # another agent's Chrome is its own
        self.assertEqual(hub.desktop_busy("ivy", "browser")["id"], first)

    def test_a_closed_agent_gets_no_browser_on_linux_and_one_from_before_the_rule_is_told_once(self):
        """D2, the pattern of os_user_rule: no new Browser box on a Linux server with the Shell box off, by validate_team
        in every path (a tick, a Shell box that goes off under it, a move); one that the team has already is kept for
        the owner's other writes, and the manager hears of it once."""
        team = json.loads(json.dumps(hub.TEAM))
        team["agents"]["ivy"]["can"] = ["web", "browser"]
        with self.assertRaises(ValueError) as caught:
            hub.validate_team(team)
        self.assertEqual((str(caught.exception), caught.exception.extra),
                         ("Ivy cannot have a browser on a Linux server while its Shell box is off: turn its Shell box "
                          "on, or its Browser box off", {"code": "browser_shell_off", "names": {"agent": "Ivy"}}))
        team["addresses"]["mini"] = "127.0.0.4"
        team["servers"]["mini"] = {"kind": "mac", "user": "dana"}
        team["agents"]["ivy"]["machine"] = "mini"       # a Mac: its browser is the Mac's own, not this rule's
        hub.validate_team(team)
        hub.TEAM["agents"]["ivy"]["can"] = ["web", "browser"]         # a breach from before the rule
        team = json.loads(json.dumps(hub.TEAM))
        team["agents"]["kai"]["title"] = "Research"
        hub.validate_team(team)                         # the owner's other writes go on
        team["agents"]["kai"]["can"] = ["web", "browser"]
        with self.assertRaisesRegex(ValueError, "^Kai cannot have a browser"):
            hub.validate_team(team)
        hub.browser_place_sweep(hub.now())
        hub.browser_place_sweep(hub.now())
        told = [s for s in self.said("manager") if "Browser box" in s]
        self.assertEqual(told, ["[hub] Ivy has its Browser box on box with its Shell box off, so it gets no browser "
                                "there: a browser on a Linux server needs the Shell box. Tell the owner, who can turn "
                                "its Shell box on or its Browser box off."])
        self.assertIn("gets no browser on box: a browser on a Linux server needs the agent's Shell box", self.task("ivy"))


    def test_a_place_goes_with_its_agent_when_it_moves_or_leaves_the_team(self):
        """A move keeps an open task, and a delete takes the stop's acknowledgement with the agent's events: a mark of
        the old server, or of an agent that is gone, holds no place there."""
        first = self.task("ivy")
        hub.TEAM["addresses"]["box2"] = "127.0.0.5"
        hub.TEAM["servers"]["box2"] = {"kind": "linux", "user": "fleet"}
        hub.TEAM["agents"]["ivy"]["machine"] = "box2"
        self.assertEqual(hub.browser_holders("box"), [])
        self.assertIsInstance(self.task("kai"), int)
        second = hub.q1("SELECT MAX(id) id FROM tasks")["id"]
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (second,))     # its helper never acknowledges the stop
        self.assertEqual(hub.browser_holders("box"), [second])
        del hub.TEAM["agents"]["kai"]
        self.assertEqual(hub.browser_holders("box"), [])
        hub.browser_place_sweep(hub.now())
        self.assertEqual(hub.browser_holds(), {})          # the old server's mark of ivy went too

    def test_a_rename_keeps_each_place_and_the_room_s_counts(self):
        first = self.task("ivy")
        hub.browser_room_seen("box", self.room(dict(ONE_PLACE, oom=0)), 1000.0)
        with hub.transaction():
            hub.rename_machine_rows("box", "box9")
        self.assertEqual(hub.browser_holds()[first]["server"], "box9")
        self.assertIsNotNone(hub.kv_get(hub.BROWSER_ROOM + "box9"))
        self.assertIsNone(hub.kv_get(hub.BROWSER_ROOM + "box"))

    def test_the_hub_admits_no_browser_task_that_the_helper_would_refuse(self):
        """The helper starts Chrome only where the parts are ready, for an agent that runs as its own OS user with a
        port of its own: a task admitted without them took a place, and its start was tried again for ever."""
        for room in (dict(state="missing"), dict(state="table_missing"), dict(state="unsupported")):
            self.room(ONE_PLACE, **room)
            self.assertIn("ivy gets no browser on box:", self.task("ivy"), room)
        data = self.room(ONE_PLACE)
        for change, words in ((lambda d: d["browser"].update(proof_kept=False), "cannot keep the live proof"),
                              (lambda d: d["browser"].update(ports=d["browser"]["ports"][1:]), "has no browser port there"),
                              (lambda d: d["agents"]["ivy"].update(user="fleet"), "does not run as an OS user of its own")):
            changed = json.loads(json.dumps(data))
            change(changed)
            hub.q("UPDATE server_status SET data=? WHERE server='box'", (json.dumps(changed),))
            self.assertIn(words, self.task("ivy"), words)
            self.assertEqual(hub.browser_refusal("ivy", "manager"), "Ivy cannot run a browser task on box now.")
        self.room(dict(ONE_PLACE, memory_max=None))        # no place at all, and no task that holds one
        self.assertEqual(hub.browser_refusal("ivy", "manager"), "Ivy cannot run a browser task on box now.")
        self.room(ONE_PLACE)
        hub.kv_set(hub.SERVICE_USER + "ivy", "1")
        self.assertIn("does not run as an OS user of its own there yet", self.task("ivy"))
        self.assertEqual(hub.browser_holds(), {})

    def test_one_agent_holds_one_place_however_many_browser_tasks_a_run_admits(self):
        """A duty's run admits up to three tasks at once, and the helper runs one at a time (D9): one place."""
        hub.TEAM["agents"]["kai"]["can"] = ["web"]
        self.room(dict(CX23, memory_max=6000 * MIB))
        tasks = []
        with hub.transaction():
            for _ in range(3):
                tasks.append(hub.admit_task("manager", {"owner": "ivy", "title": "Case", "details": "", "done_when": "d",
                                                        "needs": "browser", "goal": "", "goal_id": None, "parent": None,
                                                        "follows": None, "case_id": None}))
        self.assertEqual(hub.browser_holders("box"), tasks[:1])
        self.assertEqual(hub.browser_pending("box"), [])
        self.assertEqual(hub.browser_waits("ivy"), {})       # the other two wait in the helper for the one Chrome

    def test_a_lead_hears_in_its_own_task_that_a_place_is_free(self):
        """A worker's or a lead's session reads only the messages of its own task."""
        hub.TEAM["agents"]["lead"] = {"role": "lead", "runtime": "claude", "machine": "hub", "can": ["shell"]}
        own = hub.ins("INSERT INTO tasks(title,owner,requester,state,needs,attempt,created) VALUES('Lead',"
                      "'lead','manager','working','none',1,?)", (hub.now(),))
        first = self.task("ivy")
        with patch.object(hub, "lead_task", lambda agent: own if agent == "lead" else None):
            self.assertIn("The hub tells you when", hub.browser_refusal("kai", "lead", keep=True))
            self.assertNotIn("The hub tells you", hub.browser_refusal("kai", "manager"))    # a run comes again by itself
        self.closed(first)
        hub.browser_place_sweep(hub.now())
        row = hub.q1("SELECT task, text FROM events WHERE agent='lead' AND kind='say' ORDER BY id DESC LIMIT 1")
        self.assertEqual((row["task"], "browser place is free on box" in row["text"]), (own, True))

    def test_an_untick_under_a_task_that_waits_for_a_place_keeps_its_chrome_closed(self):
        """The owner can untick the Browser box under an open browser task: its helper still hears that it waits, so
        it starts no Chrome with no place, and the task takes one when one is free."""
        first = self.task("ivy")
        hub.q("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('ivy',?,?,1)", (hub.now(), hub.now() + 60))
        hub.browser_waits("ivy", closed={f"T-{first}"})
        second = self.task("kai")
        hub.q("UPDATE agent_limits SET ended=? WHERE agent='ivy'", (hub.now(),))
        hub.TEAM["agents"]["ivy"]["can"] = ["shell", "web"]
        self.assertEqual(hub.browser_waits("ivy"), {f"T-{first}": "place"})
        self.closed(second)
        self.assertEqual(hub.browser_waits("ivy"), {})
        self.assertEqual(hub.browser_holders("box"), [first])


    def test_two_browser_tasks_of_one_agent_never_lock_its_place(self):
        """D9 by the helper's own rule: of an agent's browser tasks only the one whose window is open, else the oldest,
        holds or takes a place. A duty's run admits two of ivy's; the first waits for a secret and gives its place back,
        and the second, which its helper does not start while the first has its window, takes none: kai takes it, and
        at the secret's answer the first takes it back once kai's ends."""
        hub.TEAM["agents"]["ivy"]["vault"] = "file"
        with hub.transaction():
            one, two = (hub.admit_task("manager", {"owner": "ivy", "title": "Case", "details": "", "done_when": "d",
                                                   "needs": "browser", "goal": "", "goal_id": None, "parent": None,
                                                   "follows": None, "case_id": None}) for _ in range(2))
        self.assertEqual(hub.browser_holders("box"), [one])
        hub.q("UPDATE agents SET alive=?, alive_ts=? WHERE name='ivy'", (f"T-{one}", hub.now()))
        nid = self.secret(one, saved=False)
        windows = {f"T-{one}"}
        self.assertEqual(hub.browser_waits("ivy", closed=windows, alive=windows), {f"T-{one}": "secret"})
        self.assertEqual((hub.browser_holders("box"), hub.browser_pending("box")), ([], []))
        third = self.task("kai")
        self.assertIsInstance(third, int, third)
        # no place is free now, and the first holds none: a session of the second that starts gets no Chrome
        self.assertEqual(hub.browser_waits("ivy", closed=windows, alive=windows),
                         {f"T-{one}": "secret", f"T-{two}": "place"})
        spec = json.loads(hub.q1("SELECT secret FROM needs WHERE id=?", (nid,))["secret"])
        hub.q("UPDATE needs SET secret=? WHERE id=?", (json.dumps(dict(spec, saved="bws://" + "a" * 36)), nid))
        hub.secret_wakes()
        self.assertEqual(hub.browser_pending("box"), [one])
        self.closed(third)
        hub.secret_wakes()
        self.assertEqual(hub.browser_waits("ivy", closed=set(), alive=windows), {})     # the first holds the place
        self.assertEqual(hub.browser_holders("box"), [one])
        self.assertNotIn(two, hub.browser_holds())
        # the first one's session is gone and its helper starts the second: the place is the second's, and the
        # first's mark goes, so that one Chrome holds one place
        self.assertEqual(hub.browser_waits("ivy", closed=set(), alive={f"T-{two}"}), {})
        self.assertEqual((hub.browser_holders("box"), one in hub.browser_holds()), ([two], False))
        # the first one, which is no longer the agent's active one, waits for a second secret: its answer wakes it
        # with no place, because it starts only after the second one (D9), and the place stays the second's
        hub.q("UPDATE agents SET alive=?, alive_ts=? WHERE name='ivy'", (f"T-{two}", hub.now()))   # as the poll writes
        nid = self.secret(one)
        hub.secret_wakes()
        woken = json.loads(hub.q1("SELECT secret FROM needs WHERE id=?", (nid,))["secret"]).get("woken")
        self.assertEqual((woken is not None, hub.browser_holders("box")), (True, [two]))

    def test_a_worker_s_browser_box_on_the_hub_s_own_linux_server_is_refused_and_the_manager_s_harms_nothing(self):
        team = json.loads(json.dumps(hub.TEAM))
        team["servers"]["hub"] = {"kind": "linux", "user": "fleet"}
        team["agents"]["manager"]["can"] = ["browser"]
        hub.validate_team(team, browser_ok=set())          # the manager runs no browser task
        team["hub"]["shared"] = True                       # a hub whose own server takes agents
        team["agents"]["hal"] = {"role": "worker", "runtime": "claude", "machine": "hub", "can": ["shell", "browser"]}
        with self.assertRaises(ValueError) as caught:
            hub.validate_team(team, browser_ok=set())
        self.assertEqual(caught.exception.extra, {"code": "browser_server", "names": {"server": "hub"}})

    def test_the_poll_s_closed_and_alive_lists(self):
        self.assertEqual(hub.browser_poll_sets({"browser_closed": "T-1,T-2", "alive": ""}), ({"T-1", "T-2"}, set()))
        self.assertEqual(hub.browser_poll_sets({}), (None, None))       # a helper that does not say


    def test_the_poll_route_gives_the_helper_s_closed_list_to_the_places(self):
        """The helper's poll carries browser_closed (D10): the route reads it, and a wait's place goes back only once
        the helper says that the task's Chrome is closed."""
        del hub.TEAM["agents"]["kai"]          # ivy alone on box: its address names it
        self.server.machines = True
        first = self.task("ivy")
        hub.q("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('ivy',?,?,1)", (hub.now(), hub.now() + 60))
        ref = f"T-{first}"
        code, answer = self.request(f"/events/ivy?delivery=1&after=0&wait=0&alive={ref}&browser_closed=")
        self.assertEqual((code, answer.get("waits"), hub.browser_holders("box")), (200, {ref: "limit"}, [first]), answer)
        code, answer = self.request(f"/events/ivy?delivery=1&after=0&wait=0&alive={ref}&browser_closed={ref}")
        self.assertEqual((code, hub.browser_holders("box")), (200, []), answer)

    def test_a_task_that_can_start_takes_the_free_place_before_an_older_one_that_waits(self):
        """D9 with D10: of an agent's browser tasks with no window, the oldest that waits for no secret is the next to
        start, so it takes a free place before its Chrome starts, and no second Chrome runs on one place meanwhile."""
        with hub.transaction():
            one, two = (hub.admit_task("manager", {"owner": "ivy", "title": "Case", "details": "", "done_when": "d",
                                                   "needs": "browser", "goal": "", "goal_id": None, "parent": None,
                                                   "follows": None, "case_id": None}) for _ in range(2))
        self.secret(one, saved=False)
        self.assertEqual(hub.browser_waits("ivy", closed={f"T-{one}"}, alive=set()), {f"T-{one}": "secret"})
        self.assertEqual(hub.browser_holders("box"), [two])
        # the older one's wait ends: it is the next to start again, and it takes its agent's place in the same poll,
        # with no line that its browser is closed
        hub.q("UPDATE tasks SET state='working', waiting_on=NULL WHERE id=?", (one,))
        self.assertEqual(hub.browser_waits("ivy", closed=set(), alive=set()), {})
        self.assertEqual(hub.browser_holders("box"), [one])
        self.assertEqual([s for s in self.said("ivy") if "closed until" in s], [])

    def test_a_task_that_ends_during_a_poll_keeps_its_place_until_its_session_is_confirmed_closed(self):
        """The poll reads the agent's tasks before its turn takes LOCK: a task that ends between the two holds its place
        until its session is confirmed closed, so that no other Chrome starts on it while its own still closes."""
        first = self.task("ivy")
        rows = hub.q("SELECT id, state, waiting_on, needs FROM tasks WHERE id=?", (first,))     # read while it is open
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (first,))                        # it ends meanwhile
        hub.browser_places_turn("ivy", rows, {}, set())
        self.assertEqual(hub.browser_holders("box"), [first])
        self.closed(first)
        hub.browser_place_sweep(hub.now())
        self.assertEqual(hub.browser_holders("box"), [])

    def test_a_wake_s_mark_goes_with_the_last_open_task_of_its_request(self):
        hub.TEAM["agents"]["ivy"]["vault"] = "file"
        first = self.task("ivy")
        nid = self.secret(first)
        hub.q("INSERT INTO kv(k,v) VALUES(?,?)", (hub.BROWSER_WAKE_HELD + str(nid), "1"))
        hub.browser_place_sweep(hub.now())
        self.assertIsNotNone(hub.kv_get(hub.BROWSER_WAKE_HELD + str(nid)))       # its task is open: the mark stays
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (first,))
        hub.browser_place_sweep(hub.now())
        self.assertIsNone(hub.kv_get(hub.BROWSER_WAKE_HELD + str(nid)))


if __name__ == "__main__":
    unittest.main()

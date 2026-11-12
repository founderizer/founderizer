"""A machine going offline wakes the manager once per offline episode. In-process hub, explicit times; no AI."""
import json
import unittest
from unittest.mock import patch

import hub
from test_ui_api import OwnerAPI


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Offline(name) for name in Offline.__dict__ if name.startswith("test_"))


class Offline(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM["agents"].update(vps=dict(role="worker", runtime="codex", machine="vps"),
                                  lead=dict(role="lead", runtime="claude", machine="vps"))
        self.t0 = 1_800_000_000.0
        for p in (patch.object(hub, "STARTED", self.t0 - 3600), patch.dict(hub.CFG, {"offline_after": 90})):
            p.start()
            self.addCleanup(p.stop)

    def seen(self, name, at):
        hub.know(name)
        hub.q("UPDATE agents SET last_seen=? WHERE name=?", (at, name))

    def told(self):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent='manager' AND kind='say' ORDER BY id")]

    def test_one_message_per_offline_episode_with_the_open_tasks(self):
        self.seen("vps", self.t0 - 100)
        hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('Work','vps','manager','working',?)",
                (self.t0,))
        hub.offline_sweep(self.t0)
        hub.offline_sweep(self.t0 + 600)
        self.assertEqual(len(self.told()), 1)
        self.assertIn("[hub] vps's machine went offline", self.told()[0])
        self.assertIn("Its open tasks: T-1.", self.told()[0])

    def test_a_machine_that_goes_offline_again_with_nothing_between_is_a_quiet_message(self):
        """Plan C10: no 30-minute mute. Each episode is told, and one with nothing on that machine since the last
        notice wakes nobody; new work, an attempt that came up or a task that ended between the two wake the manager
        again."""
        def quiet():
            return [bool(json.loads(r["extra"] or "{}").get("quiet")) for r in
                    hub.q("SELECT extra FROM events WHERE agent='manager' AND kind='say' ORDER BY id")]
        self.seen("vps", self.t0 - 100)
        hub.offline_sweep(self.t0)
        self.seen("vps", self.t0 + 300)                     # back, then gone again: a flapping machine
        hub.offline_sweep(self.t0 + 500)
        self.assertEqual(quiet(), [False, True])
        self.seen("vps", self.t0 + 2000)
        hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('Work','vps','manager','working',?)",
                (self.t0 + 1500,))                          # new work went to it
        hub.offline_sweep(self.t0 + 2200)
        self.assertEqual(quiet(), [False, True, False])
        self.assertIn("Its open tasks: T-1.", self.told()[2])

    def test_online_never_seen_manager_and_hub_start_are_quiet(self):
        self.seen("vps", self.t0 - 30)                      # online
        hub.know("lead")                                    # never checked in
        self.seen("manager", self.t0 - 1000)                # the manager is not a machine it must be told about
        hub.offline_sweep(self.t0)
        self.assertEqual(self.told(), [])
        self.seen("vps", self.t0 - 100)
        with patch.object(hub, "STARTED", self.t0 - 60):    # the hub just started: helpers are checking in again
            hub.offline_sweep(self.t0)
        self.assertEqual(self.told(), [])

    def test_a_lead_is_a_machine_too(self):
        self.seen("lead", self.t0 - 100)
        hub.offline_sweep(self.t0)
        self.assertEqual(len(self.told()), 1)
        self.assertIn("[hub] lead's machine went offline", self.told()[0])


if __name__ == "__main__":
    unittest.main()

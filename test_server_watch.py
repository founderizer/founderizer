"""Each server against its own baseline (the owner, 3 November 2026: Add server ends at the baseline, and "this app needs
to work for ANY user"): the server's reading says what holds, and the hub tells the manager once when something stops
holding and once when it holds again, with the words that send it first to the agent whose duty covers that server.
No monitoring host and no outside alert route is needed. Against a local hub with a temporary Fleet repository, as
test_servers."""
import json
import unittest
from unittest.mock import patch

import hub
from test_servers import NEW, Servers

DAY = 86400


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(ServerWatch(name) for name in ServerWatch.__dict__ if name.startswith("test_"))


class ServerWatch(Servers):
    """box is a Linux server at NEW with no agent, whose service reads."""

    GOOD = {"unattended_upgrades": True, "pending_security": 0, "reboot_required": False, "firewall": "active",
            "tailscale": True, "ssh_keys_only": True, "npm_rule": None}

    def setUp(self):
        super().setUp()
        hub.kv_set("server_watch", None)
        # The hub's own machine ("hub", which carries the manager and did not join) is measured by the hub itself: here
        # with a load that this test sets, never this machine's own.
        self.hub_load = self.load()
        patcher = patch.object(hub.lifecycle, "machine_load", lambda platform: dict(self.hub_load))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.joined("box", "linux")
        self.t0 = hub.now()
        hub.q("UPDATE server_keys SET created=? WHERE server='box'", (self.t0 - 2 * hub.JOIN_GRACE,))

    def report(self, name="box", source=NEW, os_name="Ubuntu 26.04.1 LTS", load=None, **security):
        sec = dict(self.GOOD, **dict({"upgraded_at": self.t0 - 3600}, **security))
        status, answer = self.service(f"/server/{name}/status", {
            "revision": hub.kit_revision(fresh=True), "os": {"name": os_name},
            "runtimes": {"claude": {"version": "2.1", "signed_in": True}}, "access": {"user": "fleet"},
            "security": {k: v for k, v in sec.items() if v != "absent"}, **({"load": load} if load else {})},
            source=source)
        self.assertEqual(status, 200, answer)

    @staticmethod
    def load(disk=30, memory=25):
        """A reading's load (lifecycle.machine_load) with this share of a 40 GB disk and of 4 GB of memory in use."""
        gib = 1024 ** 3
        return {"cpu_percent": 5.0, "memory_used": memory * 4 * gib // 100, "memory_total": 4 * gib,
                "disk_used": disk * 40 * gib // 100, "disk_total": 40 * gib}

    def sweep(self, t0=None, fresh=True):
        """One pass at t0; with fresh, the server reported at t0 too, as its service does every few minutes."""
        t0 = self.t0 if t0 is None else t0
        if fresh:
            hub.q("UPDATE server_status SET reported=? WHERE server='box'", (t0,))
        hub.WATCH["at"] = 0.0
        with hub.LOCK:
            hub.server_watch_sweep(t0)

    def said(self):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent=? AND kind='say' AND text LIKE "
                                         "'[hub] The server %' ORDER BY id", (hub.manager_name(),))]

    def test_a_server_that_is_still_being_set_up_is_not_watched(self):
        """Its service reads it as it starts, before the join's updates, firewall and hardening: on 3 November 2026 the
        first reading of a test server had its firewall off and SSH taking passwords, minutes before both held."""
        hub.q("UPDATE server_keys SET created=? WHERE server='box'", (self.t0 - 600,))
        self.report(firewall="inactive", ssh_keys_only=False, upgraded_at=None)
        self.sweep()
        self.assertEqual(self.said(), [])
        self.sweep(self.t0 + hub.JOIN_GRACE)
        self.assertIn("box needs care: its firewall is off; its SSH lets passwords in.", self.said()[-1])

    def test_a_server_that_holds_its_baseline_says_nothing(self):
        self.report()
        self.sweep()
        self.assertEqual(self.said(), [])
        self.assertIsNone(hub.kv_get("server_watch"))

    def test_what_stops_holding_is_said_once_and_again_once_when_it_holds(self):
        self.report(firewall="inactive", ssh_keys_only=False)
        self.sweep()
        self.sweep(self.t0 + 120)
        self.assertEqual(self.said(), [
            "[hub] The server box needs care: its firewall is off; its SSH lets passwords in. Give it to the agent "
            "whose duty covers this server; fix it yourself when no duty covers it; raise Needs-you only for a step "
            "that no agent can take."])
        self.report(ssh_keys_only=False)
        self.sweep(self.t0 + 180)
        self.report()
        self.sweep(self.t0 + 240)
        self.assertEqual(self.said()[1:], ["[hub] The server box is in order again: its firewall is on.",
                                          "[hub] The server box is in order again: its SSH takes keys only."])
        self.assertIsNone(hub.kv_get("server_watch"), "a server in order keeps no record")

    def test_security_updates_that_stop_count_from_the_last_good_one_or_from_the_join(self):
        self.report(upgraded_at=self.t0 - 2 * DAY)
        self.sweep()
        self.assertEqual(self.said(), [])
        self.report(upgraded_at=self.t0 - 4 * DAY)
        self.sweep()
        self.assertIn("no security update has ended well on it for 3 days", self.said()[-1])
        self.report(upgraded_at=None)       # no good update yet: counted from the join, which was just now
        self.sweep()
        self.assertEqual(self.said()[-1], "[hub] The server box is in order again: its security updates run again.")
        hub.q("UPDATE server_keys SET created=? WHERE server='box'", (self.t0 - 4 * DAY,))
        self.sweep()
        self.assertIn("no security update has ended well on it for 3 days", self.said()[-1])
        self.report(unattended_upgrades=False)
        self.sweep()
        self.assertEqual(self.said()[-2:], ["[hub] The server box needs care: its automatic security updates are off. "
                                            "Give it to the agent whose duty covers this server; fix it yourself when "
                                            "no duty covers it; raise Needs-you only for a step that no agent can "
                                            "take.",
                                            "[hub] The server box is in order again: its security updates run again."])

    def test_a_reading_without_the_new_facts_says_nothing_about_them(self):
        """A helper from before this release sends none of them; one that cannot read them sends null."""
        self.report(ssh_keys_only="absent", npm_rule="absent", upgraded_at="absent")
        hub.q("UPDATE server_keys SET created=? WHERE server='box'", (self.t0 - 30 * DAY,))
        self.sweep()
        self.report(ssh_keys_only=None, npm_rule=None)
        self.sweep()
        self.assertEqual(self.said(), [])

    def test_npms_rule_that_is_gone_is_said(self):
        self.report(npm_rule=False)
        self.sweep()
        self.assertIn("box needs care: npm has no seven-day rule.", self.said()[-1])

    def test_a_restart_that_waits_seven_days_is_said(self):
        self.report(reboot_required=True, upgraded_at=self.t0 + 8 * DAY)      # the daily run keeps its stamp fresh
        self.sweep()
        self.sweep(self.t0 + 6 * DAY)
        self.assertEqual(self.said(), [])
        self.sweep(self.t0 + 7 * DAY + 60)
        self.assertIn("box needs care: it has waited 7 days for a restart.", self.said()[-1])
        self.report(upgraded_at=self.t0 + 8 * DAY)
        self.sweep(self.t0 + 7 * DAY + 120)
        self.assertEqual(self.said()[-1], "[hub] The server box is in order again: it no longer waits for a restart.")

    def test_a_quiet_server_with_no_agent_is_said_and_one_with_agents_is_offline_sweeps(self):
        self.report(firewall="inactive")
        self.sweep()
        self.sweep(self.t0 + 31 * 60, fresh=False)
        self.assertEqual(self.said()[-1], "[hub] The server box needs care: it has sent no reading for 30 minutes. "
                                          "Give it to the agent whose duty covers this server; fix it yourself when no "
                                          "duty covers it; raise Needs-you only for a step that no agent can take.")
        self.assertEqual(len(self.said()), 2, "a quiet server says nothing new about its other facts")
        self.report(firewall="inactive")
        self.sweep(self.t0 + 32 * 60)
        self.assertEqual(self.said()[-1], "[hub] The server box is in order again: it sends its readings again.")
        hub.TEAM["agents"]["vps"]["machine"] = "box"            # an agent's machine is offline_sweep's
        self.addCleanup(hub.TEAM["agents"]["vps"].__setitem__, "machine", "vps")
        self.sweep(self.t0 + 64 * 60, fresh=False)
        self.assertEqual(len(self.said()), 3)

    def test_a_full_disk_is_said_once_with_its_figures_and_again_once_under_85(self):
        """The owner, 4 November 2026: the servers' figures are for the manager "to see if there are issues". From 90%,
        and in order again only under 85%, so a disk that moves about 90% is said once."""
        self.report(load=self.load(disk=91))
        self.sweep()
        self.sweep(self.t0 + 120)
        self.assertEqual(self.said(), [
            "[hub] The server box needs care: its disk is 91% full (36.4 of 40.0 GB). Give it to the agent whose duty "
            "covers this server; fix it yourself when no duty covers it; raise Needs-you only for a step that no agent "
            "can take."])
        for share in (87, 89):
            self.report(load=self.load(disk=share))
            self.sweep()
        self.report()                   # a reading that cannot say keeps what was said
        self.sweep()
        self.assertEqual(len(self.said()), 1)
        self.report(load=self.load(disk=84))
        self.sweep()
        self.assertEqual(self.said()[-1], "[hub] The server box is in order again: its disk is under 85% full.")
        self.report(load=self.load(disk=89))
        self.sweep()
        self.assertEqual(len(self.said()), 2)

    def test_a_full_server_says_what_runs_on_it(self):
        for agent in ("vps", "studio"):
            self.addCleanup(hub.TEAM["agents"][agent].__setitem__, "machine", hub.TEAM["agents"][agent]["machine"])
            hub.TEAM["agents"][agent]["machine"] = "box"
        self.report(load=self.load(memory=93, disk=95), firewall="inactive")
        self.sweep()
        self.assertEqual(self.said(), [
            "[hub] The server box needs care: its disk is 95% full (38.0 of 40.0 GB); its firewall is off; 93% of its "
            "memory is in use (3.7 of 4.0 GB). It runs Vps and Studio. Give it to the agent whose duty covers this "
            "server; fix it yourself when no duty covers it; raise Needs-you only for a step that no agent can take."])

    def test_a_mac_s_disk_is_watched_and_not_its_memory_or_its_baseline(self):
        """Activity Monitor's Memory Used is no memory pressure: a reviewer read 78% used while memory_pressure said 84%
        free. So a Mac's memory stays a figure on the screens."""
        self.report(os_name="macOS 15.6", firewall="inactive", ssh_keys_only=False, load=self.load(memory=95))
        self.sweep()
        self.assertEqual(self.said(), [])
        self.report(os_name="macOS 15.6", load=self.load(memory=95, disk=92))
        self.sweep()
        self.assertEqual(self.said(), [
            "[hub] The server box needs care: its disk is 92% full (36.8 of 40.0 GB). Give it to the agent whose duty "
            "covers this server; fix it yourself when no duty covers it; raise Needs-you only for a step that no agent "
            "can take."])

    def test_a_macos_update_that_waited_14_days_is_said_once_and_again_once_it_is_installed(self):
        """4 November 2026: macOS installs its own updates on the agents' Macs. One that it has not installed in 14 days
        waits for the owner's password, so the manager hears of it once. A reading without it says nothing."""
        day = 86400
        self.report(os_name="macOS 27.1", macos_update={"auto": True, "waiting": "27.2"})
        self.sweep()
        self.sweep(self.t0 + 13 * day)
        self.assertEqual(self.said(), [])
        self.report(os_name="macOS 27.1", macos_update={"auto": True, "waiting": "27.3"})     # a newer one in its place
        self.sweep(self.t0 + 14 * day)
        self.assertEqual(self.said(), [
            "[hub] The server box needs care: a macOS update has waited 14 days: macOS has not installed it, and only "
            "the owner can, by Screen Sharing with the Mac user's password. Give it to the agent whose duty covers this "
            "server; fix it yourself when no duty covers it; raise Needs-you only for a step that no agent can take."])
        self.report(os_name="macOS 27.1", macos_update="absent")          # an older helper: what was said holds
        self.sweep(self.t0 + 15 * day)
        self.assertEqual(len(self.said()), 1)
        self.report(os_name="macOS 27.3", macos_update={"auto": True, "waiting": None})
        self.sweep(self.t0 + 16 * day)
        self.assertEqual(self.said()[-1], "[hub] The server box is in order again: its macOS update is installed.")
        self.assertNotIn("box", json.loads(hub.kv_get("server_watch") or "{}"))
        self.report(os_name="macOS 27.3", macos_update="absent")          # and an older helper never starts one
        for days in (17, 40):
            self.sweep(self.t0 + days * day)
        self.assertEqual(len(self.said()), 2)

    def test_the_hub_s_own_machine_is_watched_with_its_own_measurement_though_it_did_not_join(self):
        """His hub's machine has no server service, and its disk holds the hub's records."""
        self.hub_load = self.load(disk=96, memory=30)
        hub.HUB_LOAD.update(at=None)
        self.sweep()
        self.assertEqual(self.said(), [
            "[hub] The server hub needs care: its disk is 96% full (38.4 of 40.0 GB). It runs Manager. Give it to the "
            "agent whose duty covers this server; fix it yourself when no duty covers it; raise Needs-you only for a "
            "step that no agent can take."])
        self.hub_load = self.load(disk=80)
        hub.HUB_LOAD.update(at=None)
        self.sweep(self.t0 + 120)
        self.assertEqual(self.said()[-1], "[hub] The server hub is in order again: its disk is under 85% full.")

    def test_a_mac_and_a_server_that_did_not_join_are_not_watched(self):
        self.report(os_name="macOS 15.6", firewall="inactive", ssh_keys_only=False)
        self.sweep()
        self.assertEqual(self.said(), [])
        self.assertNotIn("vps", json.loads(hub.kv_get("server_watch") or "{}"))


if __name__ == "__main__":
    unittest.main()

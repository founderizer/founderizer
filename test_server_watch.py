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
        self.assertIn("box needs care: its firewall is off.", self.said()[-2])
        self.assertIn("box needs care: its SSH lets passwords in.", self.said()[-1])

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
            "[hub] The server box needs care: its firewall is off. Give it to the agent whose duty covers this server; "
            "fix it yourself when no duty covers it; raise Needs-you only for a step that no agent can take.",
            "[hub] The server box needs care: its SSH lets passwords in. " + hub.MENDED_WORDS])
        self.report(ssh_keys_only=False)
        self.sweep(self.t0 + 180)
        self.report()
        self.sweep(self.t0 + 240)
        self.assertEqual(self.said()[2:], ["[hub] The server box is in order again: its firewall is on.",
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

    def test_ssh_and_npm_are_put_right_by_the_owners_mac_with_no_step_and_no_needs_you(self):
        """The owner, 14 November 2026 ("Yes, all of it"): a join kept password login, and the manager asked the owner
        for a root command. The owner's Mac runs the join's hardening again by itself, so the words ask for nothing."""
        self.report(ssh_keys_only=False, npm_rule=False)
        self.sweep()
        self.assertEqual(self.said(), ["[hub] The server box needs care: npm has no seven-day rule; its SSH lets "
                                       "passwords in. The owner's Mac puts this right by itself: while the Founderizer "
                                       "app runs there, it runs the join's hardening again on this server, as root. "
                                       "Take no step for it and raise no Needs-you item: if it still stands in 3 days, "
                                       "the hub tells you again."])
        self.report()
        self.sweep(self.t0 + 600)
        self.assertEqual(self.said()[-1], "[hub] The server box is in order again: npm has its seven-day rule; its SSH "
                                          "takes keys only.")
        self.assertIsNone(hub.kv_get("server_watch"), "a server in order keeps no record")

    def test_what_the_mac_has_not_put_right_in_3_days_is_said_once_more_and_then_a_needs_you_item_is_asked(self):
        """A Mac that stayed shut over a weekend puts it right on the Monday, before 3 days; after that, or after the
        app's six tries, the manager hears once more and raises one Needs-you item, with no step by hand."""
        fresh = self.t0 + 20 * DAY       # the daily run keeps its stamp fresh
        self.report(ssh_keys_only=False, upgraded_at=fresh)
        self.sweep()
        # What else stops holding keeps its own count.
        self.report(ssh_keys_only=False, firewall="inactive", upgraded_at=fresh)
        self.sweep(self.t0 + DAY)
        self.sweep(self.t0 + hub.MENDED_WAIT - 60)
        self.assertEqual(len(self.said()), 2)
        self.sweep(self.t0 + hub.MENDED_WAIT)
        late = ("[hub] The server box still needs care after 3 days: its SSH lets passwords in. The owner's Mac has "
                "not put it right: it does so only while the Founderizer app runs there, and it stops after six tries. "
                "Raise one Needs-you item that says this in plain words, with no step by hand in it: this server is a "
                "fleet machine, where agents run, and no agent holds it through the door.")
        self.assertEqual(self.said()[-1], late)
        for days in (4, 10):                                    # once
            self.sweep(self.t0 + days * DAY)
        self.assertEqual(self.said()[-1], late)
        self.assertEqual(len(self.said()), 3)
        # In order: a later fault counts again from its own start.
        self.report(firewall="inactive", upgraded_at=fresh)
        self.sweep(self.t0 + 11 * DAY)
        self.assertEqual(self.said()[-1], "[hub] The server box is in order again: its SSH takes keys only.")
        self.report(ssh_keys_only=False, firewall="inactive", upgraded_at=fresh)
        self.sweep(self.t0 + 12 * DAY)
        self.sweep(self.t0 + 14 * DAY)
        self.assertEqual(len(self.said()), 5)
        self.assertTrue(self.said()[-1].endswith(hub.MENDED_WORDS))
        self.sweep(self.t0 + 15 * DAY)
        self.assertEqual(self.said()[-1], late)

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

"""Each server against its own baseline (the owner, 3 November 2026: Add server ends at the baseline, and "this app needs
to work for ANY user"): the server's reading says what holds, and the hub tells the manager once when something stops
holding and once when it holds again, with the words that send it first to the agent whose duty covers that server.
No monitoring host and no outside alert route is needed. Against a local hub with a temporary Fleet repository, as
test_servers."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import hub
import lifecycle
from test_servers import HUB, KEY, NEW, OWNER, Servers, sha

DAY = 86400
# What the manager reads of the hub's own server (hub.MENDED_WORDS_HUB), word for word.
HUB_WORDS = ("The owner's Mac puts this right by itself: while the Founderizer app runs there, it gives the hub's own "
             "server the hardening of every fleet server, as root. Take no step for it and raise no Needs-you item: if "
             "it still stands in 3 days, the hub tells you again.")
# What the manager reads when a joined server's automatic updates are off, word for word.
OFF_WORDS = ("[hub] The server box needs care: its automatic security updates are off. Give it to the agent whose "
             "duty covers this server; fix it yourself when no duty covers it; raise Needs-you only for a step that no "
             "agent can take.")


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(case(name) for case in (ServerWatch, HubOwnServer, HardeningRead, UpdatesRead)
                              for name in case.__dict__ if name.startswith("test_"))


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
        # And the hub reads the SSH and npm of its own server itself on Linux (lifecycle.hardening): here what this test
        # sets, by default facts that say nothing, never this machine's own; and no read of an earlier test.
        self.hub_facts = {"ssh_keys_only": None, "npm_rule": None}
        # (create: these tests run on the code before this read too, and fail there on what they check)
        for module, name, value in ((hub.lifecycle, "hardening", lambda run=None: dict(self.hub_facts)),
                                    (hub, "HUB_HARDENING", {"read": None, "thread": None})):
            patcher = patch.object(module, name, value, create=True)
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
            asked = hub.server_watch_sweep(t0)
        if asked is not None:           # the read of the hub's own server that this pass asked for, for the next pass
            asked.join(10)
            self.assertFalse(asked.is_alive())

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

    def test_a_reading_that_leaves_a_fact_out_ends_no_fault_and_moves_no_mend(self):
        """A server's service leaves ssh_keys_only out of its reading when its systemctl gives no answer
        (lifecycle.hardening): that reading cannot say, and what was said holds. A null is still an answer that OpenSSH
        does not run there, and ends it."""
        self.report(ssh_keys_only=False)
        self.sweep()
        mend = json.loads(hub.kv_get("server_watch"))["box"]["mend"]
        self.report(ssh_keys_only="absent")
        self.sweep(self.t0 + 60)
        self.report(ssh_keys_only=False)
        self.sweep(self.t0 + 120)
        self.assertEqual(len(self.said()), 1)
        self.assertEqual(json.loads(hub.kv_get("server_watch"))["box"]["mend"], mend)
        self.report(ssh_keys_only=None)
        self.sweep(self.t0 + 180)
        self.assertEqual(self.said()[-1], "[hub] The server box is in order again: its SSH takes keys only.")
        self.assertEqual(len(self.said()), 2)

    def test_a_reading_that_cannot_read_the_automatic_updates_ends_no_fault_that_they_are_off(self):
        """15 November 2026, the owner's "Yes, fix it": a server's service leaves unattended_upgrades out of its reading
        when `systemctl is-enabled` gives no word (lifecycle.Lifecycle.security), as systemd does while it starts itself
        again, and as a call that runs out of time does. Before, the hub stored it as null, and the watch said "its
        automatic security updates are on" while they were off, then the fault again at the next reading."""
        self.report(unattended_upgrades=False)
        self.sweep()
        kept = json.loads(hub.kv_get("server_watch"))["box"]
        for t in (self.t0 + 60, self.t0 + 120):         # no word from its systemctl, in two readings
            self.report(unattended_upgrades="absent")
            self.sweep(t)
            self.assertEqual(json.loads(hub.kv_get("server_watch") or "{}").get("box"), kept, "the fault holds")
            self.assertEqual(len(self.said()), 1, "the gap makes no word")
        self.report(unattended_upgrades=False)          # it answers again, and the fault still stands
        self.sweep(self.t0 + 180)
        self.assertEqual(self.said(), [OFF_WORDS])
        self.report()                                   # "enabled": a real answer ends it
        self.sweep(self.t0 + 240)
        self.assertEqual(self.said()[1:], ["[hub] The server box is in order again: its automatic security updates "
                                          "are on."])
        self.assertIsNone(hub.kv_get("server_watch"), "a server in order keeps no record")

    def test_a_reading_that_cannot_read_the_automatic_updates_ends_no_fault_that_no_update_ended_well(self):
        """The same reading leaves "no security update has ended well for 3 days" as it was too: that fault rests on the
        automatic updates being on. A new good update ends it."""
        old = self.t0 - 4 * DAY
        self.report(upgraded_at=old)
        self.sweep()
        kept = json.loads(hub.kv_get("server_watch"))["box"]
        for t in (self.t0 + 60, self.t0 + 120):
            self.report(unattended_upgrades="absent", upgraded_at=old)
            self.sweep(t)
            self.assertEqual(json.loads(hub.kv_get("server_watch") or "{}").get("box"), kept, "the fault holds")
            self.assertEqual(len(self.said()), 1, "the gap makes no word")
        self.report(upgraded_at=old)                    # it answers again, and still no update has ended well
        self.sweep(self.t0 + 180)
        self.assertEqual(len(self.said()), 1)
        self.assertIn("box needs care: no security update has ended well on it for 3 days.", self.said()[0])
        self.report(upgraded_at=self.t0 + 200)          # a security update ends well
        self.sweep(self.t0 + 240)
        self.assertEqual(self.said()[1:], ["[hub] The server box is in order again: its security updates run again."])
        self.assertIsNone(hub.kv_get("server_watch"))

    def test_a_reading_that_cannot_read_the_automatic_updates_makes_no_fault(self):
        """On a server on which nothing was said, such a reading says nothing new, also with no good update for days."""
        hub.q("UPDATE server_keys SET created=? WHERE server='box'", (self.t0 - 30 * DAY,))
        for t in (self.t0, self.t0 + 60):
            self.report(unattended_upgrades="absent", upgraded_at=self.t0 - 10 * DAY)
            self.sweep(t)
        self.assertEqual(self.said(), [])
        self.assertIsNone(hub.kv_get("server_watch"))

    def test_the_hub_keeps_a_reading_that_leaves_the_automatic_updates_out_as_it_came(self):
        """The hub stores only what a service sent, as for ssh_keys_only: a left-out fact stays left out, and a null
        stays null (a service from before sends null when it cannot read it). The apps read both as "Not reported"."""
        self.report(unattended_upgrades="absent")
        self.assertNotIn("unattended_upgrades", self.servers()[1]["box"]["reading"]["security"])
        self.report(unattended_upgrades=None)
        security = self.servers()[1]["box"]["reading"]["security"]
        self.assertIn("unattended_upgrades", security)
        self.assertIsNone(security["unattended_upgrades"])
        self.report()
        self.assertIs(self.servers()[1]["box"]["reading"]["security"]["unattended_upgrades"], True)
        # The same check takes an agent's helper's report (GET /ui/machines).
        self.assertNotIn("unattended_upgrades", hub.validate_status({"security": {}})["security"])
        self.assertIsNone(hub.validate_status({"security": {"unattended_upgrades": None}})["security"]
                          ["unattended_upgrades"])

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


class HubOwnServer(ServerWatch):
    """The hub's own server ("hub", which carries the manager and has no server service) on a Linux hub, whose install's
    claim was two hours ago: the hub reads its SSH and npm itself, the manager hears of them as of a joined server's,
    and GET /ui/servers carries them for the owner's Mac (the owner, 14 November 2026: "get some opus 5.5 extra thread
    to fix them")."""

    def setUp(self):
        super().setUp()
        patcher = patch.object(hub, "HUB_KIND", "linux", create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        hub.kv_set("hub_claim", json.dumps({"owner": OWNER, "at": self.t0 - 2 * hub.JOIN_GRACE}))

    def own(self, t0=None, **facts):
        """One pass at t0, after the hub's read of a moment before said these facts of its own server."""
        t0 = self.t0 if t0 is None else t0
        self.hub_facts = dict({"ssh_keys_only": True, "npm_rule": None}, **facts)
        hub.HUB_HARDENING["read"] = dict(self.hub_facts, at=t0 - 5)
        self.sweep(t0)

    def test_the_hub_s_row_carries_its_own_read_of_its_server_and_no_other_row_does(self):
        """Owner API 1.170: `hardening` on the hub's own row, for the owner's Mac's sweep (ServerHardening), and null on
        each other row and before the hub's first read. Nothing else of a row changes, so no screen does."""
        _, before = self.servers()
        self.assertIsNone(before["hub"]["hardening"])
        self.hub_facts = {"ssh_keys_only": False, "npm_rule": True}
        self.sweep(fresh=False)         # the pass asks for the read, which a thread of its own makes
        _, servers = self.servers()
        self.assertEqual(servers["hub"]["hardening"], {"ssh_keys_only": False, "npm_rule": True, "at": self.t0,
                                                       "claimed_at": self.t0 - 2 * hub.JOIN_GRACE})
        self.assertEqual({n: s["hardening"] for n, s in servers.items() if n != "hub"},
                         dict.fromkeys(set(servers) - {"hub"}))
        rest = lambda rows: {n: {k: v for k, v in s.items() if k not in ("hardening", "load")} for n, s in rows.items()}
        self.assertEqual(rest(servers), rest(before))
        self.assertIsNone(servers["hub"]["reading"], "the hub's own server still has no reading of a service")
        # A second claim: the time of its claim, once the watch has kept it.
        hub.TEAM["addresses"]["owner"] = "127.0.0.11"
        self.addCleanup(hub.TEAM["addresses"].__setitem__, "owner", OWNER)
        self.assertIsNone(hub.hub_hardening_view(self.t0 + 60)["claimed_at"], "a claim that the watch has not kept")
        self.sweep(self.t0 + 60)
        self.assertEqual(hub.hub_hardening_view(self.t0 + 60)["claimed_at"], self.t0 + 60)

    def test_the_hub_s_own_ssh_and_npm_are_said_once_in_its_own_words_and_in_order_again_once(self):
        self.own(ssh_keys_only=False, npm_rule=False)
        self.own(self.t0 + 60, ssh_keys_only=False, npm_rule=False)
        self.assertEqual(self.said(), ["[hub] The server hub needs care: npm has no seven-day rule; its SSH lets "
                                       "passwords in. The owner's Mac puts this right by itself: while the Founderizer "
                                       "app runs there, it gives the hub's own server the hardening of every fleet "
                                       "server, as root. Take no step for it and raise no Needs-you item: if it still "
                                       "stands in 3 days, the hub tells you again."])
        self.own(self.t0 + 120, ssh_keys_only=True, npm_rule=False)
        self.own(self.t0 + 180, ssh_keys_only=True, npm_rule=True)
        self.own(self.t0 + 240, ssh_keys_only=True, npm_rule=True)
        self.assertEqual(self.said()[1:], ["[hub] The server hub is in order again: its SSH takes keys only.",
                                          "[hub] The server hub is in order again: npm has its seven-day rule."])
        self.assertIsNone(hub.kv_get("server_watch"), "a server in order keeps no record")

    def test_what_the_mac_has_not_put_right_on_the_hub_s_server_in_3_days_is_said_once_more(self):
        self.own(ssh_keys_only=False)
        self.own(self.t0 + hub.MENDED_WAIT - 60, ssh_keys_only=False)
        self.assertEqual(len(self.said()), 1)
        for t in (self.t0 + hub.MENDED_WAIT, self.t0 + 4 * DAY, self.t0 + 10 * DAY):
            self.own(t, ssh_keys_only=False)
        self.assertEqual(self.said()[1:], [
            "[hub] The server hub still needs care after 3 days: its SSH lets passwords in. The owner's Mac has not put "
            "it right: it does so only while the Founderizer app runs there, and it stops after six tries. Raise one "
            "Needs-you item that says this in plain words, with no step by hand in it: this is the hub's own server, "
            "where the hub runs, and the owner's Mac is what puts its SSH and npm right."])

    def test_the_hub_s_own_server_is_not_judged_in_the_hour_after_its_claim(self):
        """Its install hardens it after the claim (hub.sh's step 15 comes after its security updates), and the hub runs
        from the claim on. The first pass of a new hub keeps the claim at the oldest line of its log, else at its own
        time; a second claim is a new owner's address in team.json; and a restore of its records counts as one."""
        hub.kv_set("hub_claim", None)
        hub.q("DELETE FROM log")
        self.own(ssh_keys_only=False)
        self.assertEqual(json.loads(hub.kv_get("hub_claim")), {"owner": OWNER, "at": self.t0})
        self.own(self.t0 + hub.JOIN_GRACE - 60, ssh_keys_only=False)
        self.assertEqual(self.said(), [])
        self.own(self.t0 + hub.JOIN_GRACE, ssh_keys_only=False)
        self.assertEqual(self.said(), ["[hub] The server hub needs care: its SSH lets passwords in. "
                                       + HUB_WORDS])
        # A second claim: what was said holds for its hour, and nothing is said in it.
        hub.TEAM["addresses"]["owner"] = "127.0.0.11"
        self.addCleanup(hub.TEAM["addresses"].__setitem__, "owner", OWNER)
        t1 = self.t0 + 2 * hub.JOIN_GRACE
        for t in (t1, t1 + 600, t1 + hub.JOIN_GRACE - 60):
            self.own(t, ssh_keys_only=True)
        self.assertEqual(len(self.said()), 1)
        self.own(t1 + hub.JOIN_GRACE, ssh_keys_only=True)
        self.assertEqual(self.said()[-1], "[hub] The server hub is in order again: its SSH takes keys only.")
        # A restore of its records (take_restore keeps its time).
        t2 = t1 + 2 * hub.JOIN_GRACE
        hub.kv_set("restored_at", t2)
        self.own(t2 + 60, ssh_keys_only=False)
        self.own(t2 + hub.JOIN_GRACE - 60, ssh_keys_only=False)
        self.assertEqual(len(self.said()), 2)
        self.own(t2 + hub.JOIN_GRACE, ssh_keys_only=False)
        self.assertEqual(len(self.said()), 3)

    def test_a_hub_from_before_the_claim_record_counts_from_the_oldest_line_of_its_log(self):
        hub.kv_set("hub_claim", None)
        hub.q("DELETE FROM log")
        hub.q("INSERT INTO log(ts,agent,what) VALUES(?,?,?)", (self.t0 - 30 * DAY, "hub", "the first start"))
        self.own(ssh_keys_only=False)
        self.assertEqual(json.loads(hub.kv_get("hub_claim")), {"owner": OWNER, "at": self.t0 - 30 * DAY})
        self.assertEqual(len(self.said()), 1)

    def test_a_read_that_does_not_count_keeps_what_was_said(self):
        """None yet after a start of the hub, or older than MACHINE_STALE: nothing ends and nothing starts."""
        self.own(ssh_keys_only=False)
        hub.HUB_HARDENING["read"] = None
        self.hub_facts = {"ssh_keys_only": True, "npm_rule": True}
        self.sweep(self.t0 + 60)
        hub.HUB_HARDENING["read"] = dict(self.hub_facts, at=self.t0 + 120 - hub.MACHINE_STALE)
        self.sweep(self.t0 + 120)
        self.assertEqual(len(self.said()), 1)
        self.assertEqual(json.loads(hub.kv_get("server_watch"))["hub"]["told"], ["ssh"])

    def test_a_read_in_which_systemctl_gives_no_answer_ends_no_fault_and_moves_no_mend(self):
        """The verifier's case of 14 November 2026: systemd answers nothing while it starts itself again, and the read
        leaves SSH out (lifecycle.hardening). Before, it read as "OpenSSH does not run": a false "in order again", the
        same fault said again, and the 3 days of MENDED_WAIT counted again from it. A real answer that OpenSSH does not
        run (masked) still ends it."""
        self.own(ssh_keys_only=False)
        mend = json.loads(hub.kv_get("server_watch"))["hub"]["mend"]
        self.hub_facts = {"npm_rule": None}             # no answer from systemctl, in this read and the next
        for t in (self.t0 + 60, self.t0 + 120):
            hub.HUB_HARDENING["read"] = dict(self.hub_facts, at=t - 5)
            self.sweep(t)
        self.assertNotIn("ssh_keys_only", self.servers()[1]["hub"]["hardening"], "the app's sweep reads no fact")
        self.own(self.t0 + 180, ssh_keys_only=False)    # systemctl answers again, and the fault still stands
        self.assertEqual(len(self.said()), 1)
        self.assertEqual(json.loads(hub.kv_get("server_watch"))["hub"]["mend"], mend)
        self.own(self.t0 + hub.MENDED_WAIT, ssh_keys_only=False)
        self.assertTrue(self.said()[-1].startswith("[hub] The server hub still needs care after 3 days: its SSH lets "
                                                   "passwords in."), self.said()[-1])
        self.own(self.t0 + hub.MENDED_WAIT + 60, ssh_keys_only=None)
        self.assertEqual(self.said()[-1], "[hub] The server hub is in order again: its SSH takes keys only.")
        self.assertEqual(len(self.said()), 3)

    def test_a_hub_on_a_mac_reads_nothing_of_its_ssh_and_says_nothing(self):
        """A Mac's SSH and npm are no baseline of the fleet's, and the hub reads them nowhere but on Linux."""
        with patch.object(hub, "HUB_KIND", "mac"):
            self.hub_facts = {"ssh_keys_only": False, "npm_rule": False}
            for minutes in (0, 1, 2):
                self.sweep(self.t0 + minutes * 60)
            self.assertIsNone(hub.HUB_HARDENING["read"])
            self.assertIsNone(hub.HUB_HARDENING["thread"])
            self.assertIsNone(self.servers()[1]["hub"]["hardening"])
        self.assertEqual(self.said(), [])

    def test_a_hub_whose_openssh_does_not_run_says_nothing_of_its_ssh(self):
        """Its SSH is Tailscale's own, as on a hub where hub.sh masked OpenSSH: lifecycle.hardening reads null, which
        says nothing, also over days; npm is still its own fact."""
        for t in (self.t0, self.t0 + 60, self.t0 + 120, self.t0 + 4 * DAY):
            self.own(t, ssh_keys_only=None, npm_rule=None)
        self.assertEqual(self.said(), [])
        self.own(self.t0 + 4 * DAY + 60, ssh_keys_only=None, npm_rule=False)
        self.assertEqual(self.said(), ["[hub] The server hub needs care: npm has no seven-day rule. "
                                       + HUB_WORDS])

    def test_a_hub_with_a_server_service_of_its_own_says_each_thing_once_by_its_own_read(self):
        """A hub whose own server also has a server service (FLEET_HUB_SERVER=shared) has a reading of its own too: SSH
        and npm still come from the hub's own read alone, so a thing is never said twice, nor in the words of another
        server, and the reading says what it says of the rest."""
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('hub',?,?)", (sha(KEY), self.t0 - 2 * hub.JOIN_GRACE))
        self.report("hub", source=HUB, ssh_keys_only=False, npm_rule=False, firewall="inactive")
        self.own(ssh_keys_only=False, npm_rule=True)
        self.own(self.t0 + 60, ssh_keys_only=False, npm_rule=True)
        self.assertEqual(self.said(), [
            "[hub] The server hub needs care: its firewall is off. Give it to the agent whose duty covers this server; "
            "fix it yourself when no duty covers it; raise Needs-you only for a step that no agent can take.",
            "[hub] The server hub needs care: its SSH lets passwords in. " + HUB_WORDS])
        self.report("hub", source=HUB, ssh_keys_only=True, npm_rule=True, firewall="inactive")
        self.own(self.t0 + 120, ssh_keys_only=False, npm_rule=True)
        self.assertEqual(len(self.said()), 2, "its service's reading ends nothing that the hub's own read still says")
        self.own(self.t0 + 180, ssh_keys_only=True, npm_rule=True)
        self.own(self.t0 + 240, ssh_keys_only=True, npm_rule=True)
        self.assertEqual(self.said()[2:], ["[hub] The server hub is in order again: its SSH takes keys only."])

    def test_a_service_record_made_again_ends_no_fault_that_only_a_reading_says(self):
        """The session "One server for all: the hub's open parts" saw it on a real server, 15 November 2026: the
        installer's step that makes the hub's server service again (`hubsetup.py hub-server`, after a lost key file)
        writes that service's record again, so for an hour the watch has no reading of it, and it said "in order again"
        for a fault that nothing had read. A restore that keeps that record does the same. What only a reading says
        holds through that hour, and it is not said again after it."""
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('hub',?,?)", (sha(KEY), self.t0 - 2 * hub.JOIN_GRACE))
        self.report("hub", source=HUB, firewall="inactive", unattended_upgrades=False)
        self.own()
        self.assertEqual(len(self.said()), 1)           # its firewall off and its updates off, in one message
        kept = json.loads(hub.kv_get("server_watch"))["hub"]
        made_again = self.t0 + 60
        hub.q("UPDATE server_keys SET created=? WHERE server='hub'", (made_again,))
        for t in (made_again + 60, made_again + hub.JOIN_GRACE - 60):
            self.own(t)
            self.assertEqual(json.loads(hub.kv_get("server_watch") or "{}").get("hub"), kept, "the faults hold")
        self.assertEqual(len(self.said()), 1, "the hour says nothing")
        later = made_again + hub.JOIN_GRACE + 60
        self.report("hub", source=HUB, firewall="inactive", unattended_upgrades=False)
        hub.q("UPDATE server_status SET reported=? WHERE server='hub'", (later,))
        self.own(later)
        self.assertEqual(len(self.said()), 1, "a reading after the hour says the same faults no second time")
        self.report("hub", source=HUB)
        hub.q("UPDATE server_status SET reported=? WHERE server='hub'", (later + 60,))
        self.own(later + 60)
        self.assertEqual(self.said()[1:], ["[hub] The server hub is in order again: its firewall is on; its automatic "
                                          "security updates are on."])

    def test_the_hub_s_own_disk_is_watched_while_a_service_of_its_own_is_quiet(self):
        """The lane "Hub: the manager's name, agents on the hub's server" (UI-API.md 1.168, open point 4): a hub's server
        with a service of its own is watched as a joined server, and while that service sends no reading the watch read
        nothing new, so a disk that filled was not said. The hub measures its own disk and memory itself (server_load):
        those count whatever its service says. A restore that left the service's key behind made the same silence."""
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('hub',?,?)", (sha(KEY), self.t0 - 2 * hub.JOIN_GRACE))
        self.report("hub", source=HUB)
        quiet = self.t0 + hub.SERVER_QUIET + 60         # its service's newest reading is older than 30 minutes now
        self.hub_load = self.load(disk=96, memory=95)   # the disk and the memory of a Linux hub: both are measured
        hub.HUB_LOAD.update(at=None)
        self.sweep(quiet)
        self.assertEqual(self.said(), [
            "[hub] The server hub needs care: its disk is 96% full (38.4 of 40.0 GB); 95% of its memory is in use (3.8 "
            "of 4.0 GB). It runs Manager. Give it to the agent whose duty covers this server; fix it yourself when no "
            "duty covers it; raise Needs-you only for a step that no agent can take."])
        self.hub_load = self.load(disk=80, memory=80)   # and both end, while the service is still quiet
        hub.HUB_LOAD.update(at=None)
        self.sweep(quiet + 120)
        self.assertEqual(self.said()[-1], "[hub] The server hub is in order again: its disk is under 85% full; its memory "
                                          "in use is under 85%.")
        self.assertEqual(len(self.said()), 2)
        self.assertIsNone(hub.kv_get("server_watch"), "a server in order keeps no record")


class HardeningRead(unittest.TestCase):
    """lifecycle.hardening, with which a server's service reads its SSH and npm and the hub reads its own server's: the
    state of OpenSSH from systemctl, then sshd's own files, as any user reads them."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="fleet-hardening-")
        self.addCleanup(folder.cleanup)
        self.etc = Path(folder.name)
        (self.etc / "sshd_config.d").mkdir()
        (self.etc / "sshd_config").write_text("Include sshd_config.d/*.conf\nKbdInteractiveAuthentication no\n")
        for name, value in (("SSHD_CONFIG", str(self.etc / "sshd_config")), ("NPMRC", str(self.etc / "npmrc"))):
            patcher = patch.object(lifecycle, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.npm = []
        patcher = patch.object(lifecycle, "npm_rule", lambda path: self.npm.append(path) or True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.asked = []

    def run_says(self, out, code=0):
        def run(argv, timeout=20, cwd=None):
            self.asked.append(argv)
            return code, out, ""
        return run

    def test_openssh_from_its_socket_or_its_service_is_read_from_its_files(self):
        for says in ("inactive\nactive\n", "active\nactive\n", "active\ninactive\n"):
            self.assertEqual(lifecycle.hardening(self.run_says(says)), {"ssh_keys_only": False, "npm_rule": True})
        (self.etc / "sshd_config.d" / "10-fleet-hardening.conf").write_text("PasswordAuthentication no\n")
        self.assertEqual(lifecycle.hardening(self.run_says("inactive\nactive\n", code=3)),
                         {"ssh_keys_only": True, "npm_rule": True})
        self.assertEqual(self.asked[0], ["systemctl", "is-active", "ssh.service", "ssh.socket"])
        self.assertEqual(self.npm, [str(self.etc / "npmrc")] * 4)

    def test_openssh_that_does_not_run_says_nothing_of_its_files(self):
        """Masked or stopped, as on a hub that Tailscale's own SSH serves: systemctl's answer, a state for each unit."""
        for says in ("inactive\ninactive\n", "failed\ninactive\n", "activating\ninactive\n"):
            self.assertEqual(lifecycle.hardening(self.run_says(says, 3)), {"ssh_keys_only": None, "npm_rule": True})

    def test_a_systemctl_with_no_answer_leaves_the_fact_out(self):
        """systemd answers nothing for a second or two while it starts itself again (an update of systemd or libc6), and
        _run gives the same for a call that runs out of time: such a read cannot say, so it leaves ssh_keys_only out,
        where a null would end a fault that still stands. Also half an answer. npm's fact is its own."""
        bus = self.run_says("", 1)
        self.assertEqual(lifecycle.hardening(bus), {"npm_rule": True})
        late = lambda argv, timeout=20, cwd=None: lifecycle._run(["sleep", "5"], timeout=0.2)      # the real _run
        self.assertEqual(late(["systemctl"])[:2], (1, ""))
        self.assertEqual(lifecycle.hardening(late), {"npm_rule": True})
        self.assertEqual(lifecycle.hardening(self.run_says("inactive\n", 3)), {"npm_rule": True})
        # And a server's own reading, which takes the same function: the fact is left out of it too.
        life = lifecycle.Lifecycle("/kit", None, {"role": "worker", "runtime": "claude"}, None, None, run=bus,
                                   platform_name="linux")
        self.assertNotIn("ssh_keys_only", life.security())
        self.assertIs(life.security()["npm_rule"], True)

    def test_a_server_s_own_reading_takes_the_same_function(self):
        life = lifecycle.Lifecycle("/kit", None, {"role": "worker", "runtime": "claude"}, None, None,
                                   run=self.run_says("inactive\nactive\n"), platform_name="linux")
        with patch.object(lifecycle, "hardening", lambda run: {"ssh_keys_only": "by hardening", "npm_rule": "too"}):
            reading = life.security()
        self.assertEqual((reading["ssh_keys_only"], reading["npm_rule"]), ("by hardening", "too"))



class UpdatesRead(unittest.TestCase):
    """The automatic updates in a server's own reading (lifecycle.Lifecycle.security): systemctl's word for the unit,
    and no fact at all where it gives none."""

    @staticmethod
    def reading(answer, platform="linux"):
        """One reading whose `systemctl is-enabled unattended-upgrades` answers `answer`: (status, standard output), or
        a call that gives the run's own answer. Every other command of the reading says nothing here."""
        def run(argv, timeout=20, cwd=None):
            if argv[:2] == ["systemctl", "is-enabled"]:
                return answer() if callable(answer) else (answer[0], answer[1], "")
            return 1, "", ""
        life = lifecycle.Lifecycle("/kit", "box", {"role": "worker", "runtime": "claude"}, None, None, run=run,
                                   platform_name=platform)
        return life.security()

    def test_systemctl_s_word_is_the_fact(self):
        self.assertIs(self.reading((0, "enabled\n"))["unattended_upgrades"], True)
        for word in ("disabled", "masked", "static"):
            self.assertIs(self.reading((1, word + "\n"))["unattended_upgrades"], False, word)

    def test_no_word_from_systemctl_leaves_the_fact_out(self):
        """A bus that does not answer while systemd starts itself again (status 1, nothing on standard output), and a
        call that runs out of time, which the real _run gives in the same way: such a reading cannot say."""
        self.assertNotIn("unattended_upgrades", self.reading((1, "")))
        self.assertNotIn("unattended_upgrades", self.reading((1, " \n")))
        late = lambda: lifecycle._run(["sleep", "5"], timeout=0.2)     # the real _run, with a call that runs out of time
        self.assertEqual(late()[:2], (1, ""))
        self.assertNotIn("unattended_upgrades", self.reading(late))

    def test_a_mac_keeps_the_fact_as_null(self):
        """A Mac has no unattended-upgrades and reads no systemctl: its reading keeps the null of before."""
        self.assertIsNone(self.reading((1, ""), platform="darwin")["unattended_upgrades"])


if __name__ == "__main__":
    unittest.main()

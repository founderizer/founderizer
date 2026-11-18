"""Each server against its own baseline (the owner, 3 November 2026: Add server ends at the baseline, and "this app needs
to work for ANY user"): the server's reading says what holds, and the hub tells the manager once when something stops
holding and once when it holds again, with the words that send it first to the agent whose duty covers that server.
No monitoring host and no outside alert route is needed. Against a local hub with a temporary Fleet repository, as
test_servers."""
import contextlib
import io
import re
import json
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import hub
import leftovers
import lifecycle
from test_servers import HUB, KEY, NEW, OWNER, FakeLife, Servers, sha

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
    return unittest.TestSuite(case(name) for case in (ServerWatch, HubOwnServer, HardeningRead, UpdatesRead,
                                                      BrowserRead)
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
        # So do the facts that the owner's Mac reads to put a server right (ServerMemory, ServerRestart in the app):
        # a fact that the hub dropped would leave each server as it is.
        for fact in ("memory_guard", "restart_guard"):
            self.assertNotIn(fact, hub.validate_status({"security": {}})["security"])
            self.assertIs(hub.validate_status({"security": {fact: False}})["security"][fact], False, fact)

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
                "Tell the owner once with message_owner, in plain words and with no step by hand, and raise no Needs-you "
                "item: this server is a fleet machine, where agents run, and the owner's Mac is what puts its SSH and npm "
                "right, because the door's forms there do not change them.")
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
            "it right: it does so only while the Founderizer app runs there, and it stops after six tries. Tell the "
            "owner once with message_owner, in plain words and with no step by hand, and raise no Needs-you item: this "
            "is the hub's own server, where the hub runs, and the owner's Mac is what puts its SSH and npm right."])

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
        for name, value in (("SSHD_CONFIG", str(self.etc / "sshd_config")), ("NPMRC", str(self.etc / "npmrc")),
                            ("USER_SLICE_MAX", str(self.etc / "memory.max")), ("PANIC_SECONDS", str(self.etc / "panic")),
                            ("WATCHDOG_DEVICES", str(self.etc / "watchdog")),
                            ("CONTAINER_MARKS", (str(self.etc / "container"),))):
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
            self.assertEqual(lifecycle.hardening(self.run_says(says)),
                             {"ssh_keys_only": False, "npm_rule": True, "memory_guard": None, "restart_guard": None})
        (self.etc / "sshd_config.d" / "10-fleet-hardening.conf").write_text("PasswordAuthentication no\n")
        self.assertEqual(lifecycle.hardening(self.run_says("inactive\nactive\n", code=3)),
                         {"ssh_keys_only": True, "npm_rule": True, "memory_guard": None, "restart_guard": None})
        self.assertEqual(self.asked[0], ["systemctl", "is-active", "ssh.service", "ssh.socket"])
        self.assertEqual(self.npm, [str(self.etc / "npmrc")] * 4)

    def test_openssh_that_does_not_run_says_nothing_of_its_files(self):
        """Masked or stopped, as on a hub that Tailscale's own SSH serves: systemctl's answer, a state for each unit."""
        for says in ("inactive\ninactive\n", "failed\ninactive\n", "activating\ninactive\n"):
            self.assertEqual(lifecycle.hardening(self.run_says(says, 3)),
                             {"ssh_keys_only": None, "npm_rule": True, "memory_guard": None, "restart_guard": None})

    def test_a_systemctl_with_no_answer_leaves_the_fact_out(self):
        """systemd answers nothing for a second or two while it starts itself again (an update of systemd or libc6), and
        _run gives the same for a call that runs out of time: such a read cannot say, so it leaves ssh_keys_only out,
        where a null would end a fault that still stands. Also half an answer. npm's fact is its own."""
        bus, rest = self.run_says("", 1), {"npm_rule": True, "memory_guard": None, "restart_guard": None}
        self.assertEqual(lifecycle.hardening(bus), rest)
        late = lambda argv, timeout=20, cwd=None: lifecycle._run(["sleep", "5"], timeout=0.2)      # the real _run
        self.assertEqual(late(["systemctl"])[:2], (1, ""))
        self.assertEqual(lifecycle.hardening(late), rest)
        self.assertEqual(lifecycle.hardening(self.run_says("inactive\n", 3)), rest)
        # And a server's own reading, which takes the same function: the fact is left out of it too.
        life = lifecycle.Lifecycle("/kit", None, {"role": "worker", "runtime": "claude"}, None, None, run=bus,
                                   platform_name="linux")
        self.assertNotIn("ssh_keys_only", life.security())
        self.assertIs(life.security()["npm_rule"], True)

    def test_the_memory_limit_of_all_users_is_read_from_the_kernels_own_file(self):
        """True for a number of bytes, False for the kernel's "max", and None when the file cannot say: it is not
        there (a Mac, a system with no memory groups of this kind) or holds another word."""
        limit = self.etc / "memory.max"
        self.assertIsNone(lifecycle.memory_guard(str(limit)))
        for word, says in (("max\n", False), ("3473678336\n", True), ("\n", None), ("many\n", None)):
            limit.write_text(word)
            self.assertIs(lifecycle.memory_guard(str(limit)), says, word)
            self.assertIs(lifecycle.hardening(self.run_says("active\ninactive\n"))["memory_guard"], says, word)
        # A read that systemctl does not answer leaves SSH's fact out, and keeps this one, which is the kernel's own.
        limit.write_text("max\n")
        self.assertEqual(lifecycle.hardening(self.run_says("", 1)),
                         {"npm_rule": True, "memory_guard": False, "restart_guard": None})

    def test_a_server_restarts_by_itself_by_the_kernels_own_files(self):
        """True when a kernel panic restarts the server (kernel.panic is not 0, and below 0 restarts it at once) and a
        watchdog device is active, False when either is not so, so a softdog that systemd does not ping counts as none,
        and None when the kernel's file of the panic cannot say (a Mac) and in a container, whose kernel and watchdog
        devices are its host's."""
        panic, device = self.etc / "panic", self.etc / "watchdog" / "watchdog0"
        self.assertIsNone(lifecycle.restart_guard(str(panic), str(device.parent)))
        panic.write_text("10\n")
        self.assertIs(lifecycle.restart_guard(str(panic), str(device.parent)), False, "no watchdog device at all")
        device.mkdir(parents=True)
        for word, state, says in (("0\n", "active\n", False), ("10\n", "inactive\n", False), ("10\n", "active\n", True),
                                  ("-1\n", "active\n", True), ("many\n", "active\n", None)):
            panic.write_text(word)
            (device / "state").write_text(state)
            self.assertIs(lifecycle.restart_guard(str(panic), str(device.parent)), says, (word, state))
            self.assertIs(lifecycle.hardening(self.run_says("active\ninactive\n"))["restart_guard"], says, (word, state))
        (self.etc / "container").write_text("lxc\n")
        self.assertIsNone(lifecycle.hardening(self.run_says("active\ninactive\n"))["restart_guard"], "a container")

    def test_a_server_s_own_reading_takes_the_same_function(self):
        life = lifecycle.Lifecycle("/kit", None, {"role": "worker", "runtime": "claude"}, None, None,
                                   run=self.run_says("inactive\nactive\n"), platform_name="linux")
        with patch.object(lifecycle, "hardening", lambda run: {"ssh_keys_only": "by hardening", "npm_rule": "too"}):
            reading = life.security()
        self.assertEqual((reading["ssh_keys_only"], reading["npm_rule"]), ("by hardening", "too"))



class BrowserRead(unittest.TestCase):
    """A Linux server's reading of its agents' browser parts and of the room for them (build plan 04, S1b), as its
    service makes it with no root: what the owner's Mac puts in place by it, and what the hub counts places from."""

    PARTS = {"ports": "fleet-alpha 9300 5910\nfleet-beta 9301 5911\n", "table": "the table\n", "unit": "u",
             "dropin": "n", "default": "d", "origin": "o", "fixed": "f", "policy": "p", "source": "s", "key": "k"}
    APP = Path(leftovers.ROOT) / "app"      # the apps' folder, which the published repository never has
    NO_APP = "the apps' folder app/ is not in this tree (the published repository has none)"

    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="fleet-browser-")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        (self.root / "etc").mkdir()
        (self.root / "etc/os-release").write_text('NAME="Ubuntu"\nVERSION_ID="24.04"\nID=ubuntu\n')
        self.installed, self.unit, self.foreign = list(lifecycle.BROWSER_PACKAGES), "active", False
        # what systemd runs for nftables.service: the drop-in's three lines, read again after its last change
        table = lifecycle.BROWSER_PARTS["table"]
        self.systemd = {"NeedDaemonReload": "no", **{key: f"{{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f {table} ; "
                        f"ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
                        for key in ("ExecStartPost", "ExecReload", "ExecStopPost")}}
        self.extra, self.show_code = "", 0

    def put(self, **parts):
        for key, text in parts.items():
            path = self.root / lifecycle.BROWSER_PARTS[key].lstrip("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def commands(self, argv, **_):
        if argv[0] == "dpkg-query":
            # each package of this server's architecture, installed; libatomic1 on hold; and a foreign xvfb only
            return 0, "".join(f"{p}\t1.0\t{'i386' if p == 'xvfb' and self.foreign else 'amd64'}\t"
                              f"{'hi ' if p == 'libatomic1' else 'ii '}\n" for p in argv[3:] if p in self.installed), ""
        if argv[:3] == ["systemctl", "show", "nftables.service"]:
            return self.show_code, "".join(f"{k}={v}\n" for k, v in self.systemd.items()) + self.extra, ""
        return (0, self.unit + "\n", "") if argv[:2] == ["systemctl", "is-active"] else (1, "", "")

    def read(self, machine="x86_64", broker=1001):
        def broker_uid():
            if broker is None:
                raise KeyError(lifecycle.BROWSER_BROKER)
            return broker
        return lifecycle.browser_reading("linux", root=str(self.root), run=self.commands, machine=lambda: machine,
                                         broker=broker_uid)

    def test_the_parts_are_ready_only_when_each_one_is_in_place(self):
        """`missing` while a package, a file or the table's unit is not there; `ready` with the SHA-256 of each file
        and the agents' ports, which the owner's Mac compares with what it would write."""
        self.put(**self.PARTS)
        reading = self.read()
        self.assertEqual((reading["state"], reading["missing"], reading["unit"], reading["broker"], reading["added"]),
                         ("ready", [], "active", 1001, False))
        self.assertEqual(reading["files"]["ports"], sha(self.PARTS["ports"]))
        self.assertEqual(reading["ports"], [{"user": "fleet-alpha", "devtools": 9300, "screen": 5910},
                                            {"user": "fleet-beta", "devtools": 9301, "screen": 5911}])
        self.installed.remove("libatomic1")
        self.assertEqual((self.read()["state"], self.read()["missing"]), ("missing", ["libatomic1"]))
        self.installed.append("libatomic1")
        self.foreign = True             # xvfb of another architecture is not this server's xvfb
        self.assertEqual((self.read()["state"], self.read()["missing"]), ("missing", ["xvfb"]))
        self.foreign = False
        self.unit = "failed"
        self.assertEqual(self.read()["state"], "missing")
        self.unit = "active"
        (self.root / lifecycle.BROWSER_PARTS["key"].lstrip("/")).unlink()
        self.assertEqual((self.read()["state"], self.read()["files"]["key"]), ("missing", None))
        self.put(key="k", ports="fleet-alpha 9300 5910")        # no new line at its end: not of the contract
        self.assertEqual((self.read()["state"], self.read()["ports"]), ("missing", []))
        self.assertIsNone(self.read(broker=None)["broker"])

    def test_the_drop_in_counts_only_where_systemd_runs_its_lines(self):
        """A later drop-in that empties one of its lists (`systemctl edit` writes `ExecReload=`), or a drop-in that
        systemd has not read again, leaves the file in place and the table gone after the next event of
        nftables.service: the reading names it missing, and the owner's Mac writes it and reloads systemd again (a
        review of 17 November 2026)."""
        self.put(**self.PARTS)
        self.assertEqual((self.read()["state"], self.read()["files"]["dropin"]), ("ready", sha(self.PARTS["dropin"])))
        for key, value in (("ExecReload", ""), ("ExecStopPost", "{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f "
                                                                 "/etc/founderizer-egress/table.nft ; }"),
                           ("NeedDaemonReload", "yes")):
            kept = self.systemd[key]
            self.systemd[key] = value
            self.assertEqual((self.read()["state"], self.read()["files"]["dropin"]), ("missing", None), key)
            self.systemd[key] = kept
        # another part's drop-in after this one: systemd gives a line for each command of the list (live, systemd 255)
        self.extra = "ExecReload={ path=/bin/true ; argv[]=/bin/true ; ignore_errors=yes ; }\n"
        self.assertEqual(self.read()["state"], "ready")
        self.extra, self.show_code = "", 1                  # a systemctl that did not answer proves nothing
        self.assertEqual((self.read()["state"], self.read()["files"]["dropin"]), ("missing", None))

    @unittest.skipUnless(APP.is_dir(), NO_APP)
    def test_the_app_and_the_server_name_the_same_files(self):
        """The owner's Mac writes the parts at the paths of ServerBrowser.swift, and the server reads them at those
        of BROWSER_PARTS: a path that differs reads as missing at every reading, and the Mac installs at every round."""
        swift = (self.APP / "Sources/FleetCore/ServerBrowser.swift").read_text()
        paths = dict(re.findall(r'public static let (\w+)Path = "([^"]+)"', swift))
        names = re.search(r"public static let parts = \[(.*?)\]", swift, re.S).group(1)
        parts = {key: paths[name] for key, name in re.findall(r'"(\w+)": (\w+)Path', names)}
        self.assertEqual(parts, lifecycle.BROWSER_PARTS)

    def test_only_x86_ubuntu_24_04_and_26_04_are_supported(self):
        self.assertEqual(self.read(machine="aarch64"), {"state": "unsupported"})
        (self.root / "etc/os-release").write_text('NAME="Debian GNU/Linux"\nVERSION_ID="13"\nID=debian\n')
        self.assertEqual(self.read(), {"state": "unsupported"})
        (self.root / "etc/os-release").write_text('NAME="Ubuntu"\nVERSION_ID="26.04"\nID=ubuntu\n')
        self.assertEqual(self.read()["state"], "missing")
        self.assertIsNone(lifecycle.browser_reading("darwin"))

    def test_a_ports_file_is_read_only_as_the_contract_gives_it(self):
        good = "fleet-alpha 9300 5910\nfleet-beta 9399 5999\n"
        self.assertEqual(len(lifecycle.browser_ports(good)), 2)
        self.assertEqual(lifecycle.browser_ports(""), [])
        for bad in ("fleet-alpha 9300 5910", "fleet-vault 9300 5910\n", "fleet-alpha 9400 5910\n",
                    "fleet-alpha 9300 5909\n", "fleet-alpha 9300 5910\nfleet-beta 9300 5911\n",
                    "fleet-alpha 9300 5910\nfleet-alpha 9301 5911\n", "fleet-alpha 9300  5910\n",
                    "root 9300 5910\n", "fleet-alpha 09300 5910\n", "fleet-alpha 9300 5910\n\n"):
            self.assertIsNone(lifecycle.browser_ports(bad), bad)

    def test_the_room_is_the_kernels_own_words_of_user_slice(self):
        """D6's inputs: the swap, the slice's limits ("max" is none), its swap in use and at its peak, and the counts of
        its own ends, of a full swap and of the time that all its processes waited."""
        slice_ = self.root / "sys/fs/cgroup/user.slice"
        slice_.mkdir(parents=True)
        (self.root / "proc").mkdir()
        (self.root / "proc/meminfo").write_text("MemTotal:        3910656 kB\nSwapTotal:       1955836 kB\n")
        for name, text in (("memory.max", "3473678336\n"), ("memory.swap.max", "max\n"),
                           ("memory.swap.current", "52428800\n"), ("memory.swap.peak", "1073741824\n"),
                           ("memory.events.local", "low 0\nhigh 0\nmax 35454\noom 1\noom_kill 1\n"),
                           ("memory.swap.events", "high 0\nmax 0\nfail 38\n"),
                           ("memory.pressure", "some avg10=0.00 avg60=0.00 avg300=0.00 total=8123456\n"
                                               "full avg10=0.00 avg60=0.00 avg300=0.00 total=1534000\n")):
            (slice_ / name).write_text(text)
        self.assertEqual(lifecycle.room_reading("linux", root=str(self.root)), {
            "swap_total": 1955836 * 1024, "memory_max": 3473678336, "swap_max": None, "swap_current": 52428800,
            "swap_peak": 1073741824, "oom": 1, "swap_fail": 38, "full_us": 1534000})
        (slice_ / "memory.pressure").unlink()
        self.assertIsNone(lifecycle.room_reading("linux", root=str(self.root))["full_us"])
        self.assertIsNone(lifecycle.room_reading("darwin"))

    def test_a_reset_is_the_rule_only_where_a_listener_of_the_agent_is_proved(self):
        """D11: a reset proves the port rule only while the kernel lists a socket of the agent's own that listens on its
        port, because the kernel resets a try of a port where nothing listens too (a connection that ended a moment
        ago, a port bound with no listen, a listener that its agent ended), and another agent's listener would let it
        make this agent's proof hold."""
        self.assertEqual(lifecycle.browser_verdict("connected", False), "open")
        self.assertEqual(lifecycle.browser_verdict("refused", True), "holds")
        for said in ("refused", "silent"):
            self.assertEqual(lifecycle.browser_verdict(said, False), "unread", said)
        tcp = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
               "   0: 0100007F:2454 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1002  0 81\n"  # 9300
               "   1: 0100007F:2455 0100007F:C350 06 00000000:00000000 03:00000000 00000000  1002  0 0\n"   # ended
               "   2: 0A000001:2456 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1002  0 82\n"  # elsewhere
               "   3: 00000000:2457 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1002  0 83\n"  # 0.0.0.0
               "   4: 0100007F:2458 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1003  0 84\n")  # another
        listening = lambda port: lifecycle.browser_listening(port, 1002, opener=lambda *_a, **_k: io.StringIO(tcp))
        self.assertEqual([listening(p) for p in (9300, 9301, 9302, 9303, 9304)], [True, False, False, True, False])


    def test_the_kernels_whole_list_of_sockets_is_read(self):
        """An agent with many sockets pushed another agent's listener past the first 4 MiB of /proc/net/tcp, which
        was all that the proof read, and the verdict was `unread` (a review of 17 November 2026)."""
        head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        row = "{:4d}: {} 00000000:0000 {} 00000000:00000000 00:00000000 00000000  {}  0 {}\n"
        tcp = head + "".join(row.format(n, "0100007F:C000", "01", 1003, 1000 + n) for n in range(50000)) + \
            row.format(1, "0100007F:2454", "0A", 1002, 81)
        self.assertGreater(len(tcp), 1 << 22)
        self.assertTrue(lifecycle.browser_listening(9300, 1002, opener=lambda *_a, **_k: io.StringIO(tcp)))
        self.assertFalse(lifecycle.browser_listening(9300, 1003, opener=lambda *_a, **_k: io.StringIO(tcp)))
    def service(self, run=None):
        """A server service of this test's own user, whose agents' proof runs here with no sudo."""
        import server
        svc = server.Service({"name": "vps-2"}, None, kit=str(self.root / "no-kit"), home=str(self.root),
                             run=run or (lambda argv, **_: (0, "", "")), platform="linux", life=FakeLife(),
                             users=lambda user: (os.getuid(), str(self.root)))
        svc.as_agent, svc.run_folder = (lambda user, argv: argv), str(self.root / "run")
        return svc

    def test_the_proofs_own_listener_takes_the_port_and_ends_with_its_input(self):
        """server.PROOF_LISTENER as it runs, by the system's own Python (here as this test's own user, on a machine
        with no port rule): it takes the agent's lock and then the port, the try connects to it, and it ends at once
        when the service closes its input, and not after its 15 seconds, because the service cannot kill it: it runs
        as the agent, under root's sudo."""
        svc = self.service()
        with socket.socket() as free:
            free.bind(("127.0.0.1", 0))
            port = free.getsockname()[1]
        started = time.monotonic()
        self.assertEqual(svc.prove_port("fleet-alpha", port), "open")
        self.assertLess(time.monotonic() - started, 5)
        self.assertTrue((self.root / "run" / str(os.getuid()) / lifecycle.BROWSER_LOCK).is_file())

    def test_a_port_that_is_held_with_no_listener_proves_nothing(self):
        """The refused branch of the real proof: a port that a socket holds with no listen() (an agent can bind
        another's port that way) makes the listener say `taken`, and Linux resets the try (here the reset is given:
        macOS lets such a try wait); that holds only where the kernel lists a listener of the agent's own there, with
        the agent's uid."""
        svc, asked = self.service(), []
        with socket.socket() as held, patch.object(lifecycle, "browser_connect", lambda port: "refused"):
            held.bind(("127.0.0.1", 0))
            port = held.getsockname()[1]
            for listed, verdict in ((False, "unread"), (True, "holds")):
                svc.listening = lambda p, uid, listed=listed: asked.append((p, uid)) or listed
                self.assertEqual(svc.prove_port("fleet-alpha", port), verdict)
        self.assertEqual(asked, [(port, os.getuid())] * 2)

    def test_no_proof_while_the_macs_step_writes_the_ports(self):
        """The step of the owner's Mac moves a new ports file into place and then loads its table, under a lock: a
        reading in that moment would find a new port with no rule yet, call the table missing and stop every agent's
        browser. So the reading takes a shared hold of that lock, and where it stays held (only root can hold it),
        each agent's verdict is `unread`, so that no verdict of an earlier reading stays in force."""
        import fcntl
        svc = self.service()
        svc.lock_path, svc.lock_wait = str(self.root / "lock"), 0.3
        svc.proof_path = str(self.root / "proof" / "state")
        (self.root / "proof").mkdir()
        self.put(**self.PARTS)
        Path(svc.lock_path).write_text("")
        tried, parts = [], self.read()
        with patch.object(lifecycle, "browser_reading", lambda *a, **k: dict(parts)), \
                patch.object(svc, "prove_port", lambda user, port: tried.append(user) or "holds"):
            with open(svc.lock_path) as step:
                fcntl.flock(step, fcntl.LOCK_EX)
                busy = svc.browser_now()
                kept = Path(svc.proof_path).read_text()
            free = svc.browser_now()
        self.assertEqual((busy["proof"], busy["proof_kept"], busy["worker"]),
                         ({"holds": 0, "open": 0, "unread": 2}, True, os.getuid()))
        self.assertEqual(kept.splitlines()[1:], ["fleet-alpha unread", "fleet-beta unread"])
        self.assertEqual((free["proof"], tried), ({"holds": 2, "open": 0, "unread": 0}, ["fleet-alpha", "fleet-beta"]))

    def test_a_table_that_is_not_loaded_stops_the_agents_browsers(self):
        """The service's proof (server.Service.browser_proof), one verdict for each agent: one port that connects is a
        missing table, which stops each agent's browser and screen units and says `table_missing`; the verdicts go
        into the service's own file with the version of the table that they tested, and `proof_kept` says whether
        they are there for the agents' helpers. A fault in the reading of the parts never stops the server's report."""
        import server
        ran = []
        svc = server.Service({"name": "vps-2"}, None, kit=str(self.root / "no-kit"), home=str(self.root),
                             run=lambda argv, **_: ran.append(argv) or (0, "", ""), platform="linux",
                             life=FakeLife(), users=lambda user: (4000, "/home/" + user))
        keep = self.root / "proof" / "state"
        parts = {"state": "ready", "files": {"ports": "ab" * 32}, "ports": [
            {"user": "fleet-alpha", "devtools": 9300, "screen": 5910},
            {"user": "fleet-beta", "devtools": 9301, "screen": 5911}]}
        with patch.object(svc, "prove_port", side_effect=["holds", "unread"]):
            got = svc.browser_proof(dict(parts), keep=str(keep))
        self.assertEqual((got["proof"], got["proof_kept"]), ({"holds": 1, "open": 0, "unread": 1}, False))
        keep.parent.mkdir()
        for says, state, stops in ((["holds", "unread"], "ready", 0), (["unread", "open"], "table_missing", 2)):
            ran.clear()
            with patch.object(svc, "prove_port", side_effect=says):
                got = svc.browser_proof(dict(parts), keep=str(keep))
            self.assertEqual((got["state"], got["proof_kept"]), (state, True))
            self.assertEqual(keep.read_text(), f"{'ab' * 32}\nfleet-alpha {says[0]}\nfleet-beta {says[1]}\n")
            self.assertEqual(len([a for a in ran if a[-3:] == ["stop", "fleet_browser.service", "fleet_vnc.service"]]),
                             stops)
        self.assertEqual(svc.browser_proof({"state": "missing", "files": {"ports": None}, "ports": []}, keep=str(keep)),
                         {"state": "missing", "files": {"ports": None}, "ports": []})
        with patch.object(lifecycle, "browser_reading", side_effect=RuntimeError("a part of another shape")), \
                contextlib.redirect_stdout(io.StringIO()):
            reading = svc.reading()
        self.assertIsNone(reading["browser"])
        self.assertEqual(reading["os"], FakeLife().os_info())


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

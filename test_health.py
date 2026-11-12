"""Owner API 1.5: hub health and the owner's copy of the fleet. In-process hub; no fleet or AI calls."""
import hashlib
import io
import json
import os
import re
import sqlite3
import unittest
import unittest.mock
import urllib.request
import uuid
import zipfile

import hub
from test_ui_api import OwnerAPI


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Health(name) for name in Health.__dict__ if name.startswith("test_"))


class Health(OwnerAPI):
    def setUp(self):
        super().setUp()
        # The copy carries the owner's own configuration from the checkout, so give this hub a checkout of its own
        # instead of the one these tests run in.
        kit = os.path.join(self.tmp.name, "kit")
        os.makedirs(os.path.join(kit, "profiles"))
        os.makedirs(os.path.join(kit, "knowledge", "owner"))
        with open(os.path.join(kit, "team.json"), "w") as f:
            json.dump(hub.TEAM, f)
        with open(os.path.join(kit, "profiles", "manager.md"), "w") as f:
            f.write("# Profile: manager\n")
        with open(os.path.join(kit, "knowledge", "owner", "brand.md"), "w") as f:
            f.write("# Brand\n\nBlue.\n")
        hub.CFG["team_path"] = os.path.join(kit, "team.json")
        self.addCleanup(hub.CFG.pop, "team_path", None)
        # The copy's manifest counts what the hub machine holds in `~/.fleet` — the Google accounts, the App
        # key, the MCP servers, the attachments. Here that folder is this test's own and empty, never the real
        # one of the developer running it.
        for key, name in (("google_file", "google.json"), ("mcp_file", "mcp.json"),
                          ("github_app", "github-app.pem"), ("attachment_dir", "attachments")):
            hub.CFG[key] = os.path.join(self.tmp.name, "fleet-home", name)
            self.addCleanup(hub.CFG.pop, key, None)

    def health(self):
        code, data = self.request("/ui/health?db=test-generation")
        self.assertEqual(code, 200)
        return data

    def download(self, db="test-generation"):
        req = urllib.request.Request(self.base + "/ui/backup?db=" + db, headers={"X-Fleet-Client": "deterministic-test"})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, dict(e.headers), e.read()

    def confirm(self, sha256, size):
        return self.request("/ui/backups/confirm", dict(request_id=str(uuid.uuid4()), db="test-generation",
                                                        sha256=sha256, bytes=size))

    def test_backups_are_on_unless_the_team_turns_them_off(self):
        """They were off until 18 October 2026, and nothing in the app could press them: a product whose records
        have one copy on one disk cannot ship that way. The hub still writes nothing on its own machine."""
        self.assertTrue(self.health()["backups_enabled"])
        self.assertEqual(self.download()[0], 200)
        hub.TEAM["backup"] = {"enabled": False}
        data = self.health()
        self.assertFalse(data["backups_enabled"])
        self.assertNotIn("backup_missing", [w["kind"] for w in data["warnings"]])
        self.assertEqual(self.download()[0], 403)
        self.assertEqual(self.confirm("0" * 64, 1)[0], 403)

    def test_health_names_what_is_missing(self):
        data = self.health()
        self.assertFalse(data["ok"])
        kinds = [w["kind"] for w in data["warnings"]]
        self.assertIn("backup_missing", kinds)
        self.assertIn("helper_offline", kinds)
        self.assertIsNone(data["backup"])
        self.assertGreater(data["hub"]["db_bytes"], 0)
        self.assertIn("health", self.request()[1]["ui_features"])
        self.assertEqual(self.request("/ui/health?db=old")[0], 409)

    def test_a_confirmed_copy_is_the_whole_fleet_and_clears_the_warning(self):
        self.assertEqual(self.download("old")[0], 409)
        code, headers, data = self.download()
        self.assertEqual(code, 200)
        digest = hashlib.sha256(data).hexdigest()
        self.assertEqual((headers["X-Fleet-Backup-SHA256"], headers["X-Fleet-DB"]), (digest, "test-generation"))
        zf = zipfile.ZipFile(io.BytesIO(data))
        self.assertEqual(sorted(zf.namelist()),
                         ["RESTORE.md", "config/knowledge/owner/brand.md", "config/profiles/manager.md",
                          "config/team.json", "fleet.json", "fleet.sqlite3"])
        manifest = json.loads(zf.read("fleet.json"))
        self.assertEqual(manifest["format"], hub.BACKUP_FORMAT)
        self.assertEqual(manifest["fleet_id"], hub.fleet_id())
        for name, says in manifest["files"].items():
            self.assertEqual(hashlib.sha256(zf.read(name)).hexdigest(), says["sha256"], name)
        notes = zf.read("RESTORE.md").decode()
        self.assertIn("## What is NOT in it", notes)                    # it says what it does not carry
        self.assertIn("what no copy can carry, and what this one leaves out on purpose", notes)
        copy = sqlite3.connect(":memory:")
        self.addCleanup(copy.close)
        copy.deserialize(zf.read("fleet.sqlite3"))
        self.assertEqual(copy.execute("SELECT v FROM kv WHERE k='db_id'").fetchone()[0], "test-generation")
        self.assertIn("backup_missing", [w["kind"] for w in self.health()["warnings"]])   # served is not saved
        self.assertEqual(self.confirm("0" * 64, len(data))[0], 409)
        code, result = self.confirm(digest, len(data))
        self.assertEqual((code, result["backup"]["sha256"]), (200, digest))
        health = self.health()
        self.assertEqual(health["backup"]["sha256"], digest)
        self.assertNotIn("backup_missing", [w["kind"] for w in health["warnings"]])
        self.download()                                     # a newer copy was served: the old one no longer confirms
        self.assertEqual(self.confirm(digest, len(data))[0], 409)

    def test_every_warning_carries_the_way_out(self):
        """The owner, 19 October 2026: a screen that reports something wrong must carry the way to put it right.
        So the ones that are about one agent name it, which is what lets the app put a button beside the line
        instead of inventing one, and `fix` says what that button does not: a warning whose button says it all
        ("Save a copy", "Open Mini") has none (T-37, 28 October 2026)."""
        hub.TEAM["hub"] = {"machine": "hub", "port": 8765}
        hub.kv_set("integrity", "row 3 missing from index")
        hub.kv_set("schema_problems", json.dumps(["CREATE UNIQUE INDEX one: UNIQUE constraint failed"]))
        hub.kv_set("mgr_flag", "The manager session is not running. Start it again.")
        hub.kv_set("mgr_flag_kind", "down")
        hub.kv_set("mgr_flag_since", hub.now())
        hub.TEAM["addresses"]["vps"] = "127.0.0.3"
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"],
                                     "vault": "broker"}
        hub.touch("vps")                            # its helper is checking in, so only its vault is behind
        self.vault_report("vps", "c" * 64)
        with unittest.mock.patch.object(hub, "DISK_LOW", 1 << 62), \
                unittest.mock.patch.object(hub, "vault_source", return_value="a" * 64), \
                unittest.mock.patch.object(hub, "kit_revision", return_value=self.REVISION):
            warnings = {w["kind"]: w for w in self.health()["warnings"]}
        self.assertEqual(sorted(warnings), ["backup_missing", "disk_low", "helper_offline", "integrity",
                                            "machine_stale", "manager_down", "schema", "vault_behind"])
        for kind, w in warnings.items():
            if kind in ("backup_missing", "helper_offline", "machine_stale"):
                self.assertIsNone(w["fix"], kind)
            else:
                self.assertTrue(w["fix"].strip(), kind)
            self.assertTrue(w["detail"].strip(), kind)
        # The agent is there exactly when the warning is about one, and it is an agent this fleet has.
        named = {kind: w.get("agent") for kind, w in warnings.items()}
        self.assertEqual(named, {"backup_missing": None, "integrity": None, "schema": None,
                                 "helper_offline": "manager", "machine_stale": "manager",
                                 "manager_down": "manager", "disk_low": "manager", "vault_behind": "vps"})
        for kind, agent in named.items():
            if agent:
                self.assertIn(agent, hub.agents(), kind)
        # His voice, in few words: the app's title says who and what, and its button the way out.
        self.assertEqual(warnings["backup_missing"]["detail"], "None saved yet.")     # the title: No copy of your fleet
        self.assertEqual(warnings["helper_offline"]["detail"], "Silent since the hub started.")
        self.assertEqual(warnings["machine_stale"]["detail"], "No status for ten minutes.")
        # A session that is not running is the one manager warning a button settles (owner feature manager_start).
        self.assertIn("Start the session", warnings["manager_down"]["fix"])
        hub.kv_set("mgr_flag_kind", "limited")
        hub.kv_set("mgr_flag", "The manager reached its usage limit.")
        limited = next(w for w in self.health()["warnings"] if w["kind"] == "manager_limited")
        self.assertEqual(limited["fix"], "If its session shows a limit menu, answer it there.")
        hub.kv_set("mgr_flag_kind", "silent")
        silent = next(w for w in self.health()["warnings"] if w["kind"] == "manager_silent")
        self.assertIn("Open Manager", silent["fix"])
        # the vault: his words, and no revision, path or command (those are WORKER-INSTALL.md's)
        self.assertEqual((warnings["vault_behind"]["detail"], warnings["vault_behind"]["fix"]),
                         ("The vault on vps has not taken the last update.",
                          "It updates itself within ten minutes; tell us if it does not."))
        # The hub's disk is the hub machine's disk, so that warning leads to the agent on that machine; a hub
        # whose machine carries no agent names none, and the app then has nowhere to send him.
        hub.TEAM["hub"] = {"machine": "nowhere", "port": 8765}
        with unittest.mock.patch.object(hub, "DISK_LOW", 1 << 62):
            disk = next(w for w in self.health()["warnings"] if w["kind"] == "disk_low")
        self.assertNotIn("agent", disk)
        self.assertTrue(disk["fix"])

    def test_the_hub_s_disk_says_its_size_and_the_server_it_is_on(self):
        """The owner, 4 November 2026: "it is also not clear what Free Space means, and how much we're using, and where
        it is"."""
        hub.TEAM["hub"] = {"machine": "worker-2", "port": 8765}
        self.addCleanup(hub.TEAM.pop, "hub", None)
        disk = type("Stat", (), {"f_bavail": 16490426, "f_blocks": 19602196, "f_frsize": 4096})
        with unittest.mock.patch.object(hub.os, "statvfs", lambda path: disk):
            facts = self.health()["hub"]
        self.assertEqual((facts["disk_free_bytes"], facts["disk_total_bytes"], facts["machine"]),
                         (16490426 * 4096, 19602196 * 4096, "worker-2"))

    def allowance(self, agent, used, hours_left, key="anthropic:" + "d" * 32, minutes=10080, age=0, windows=None):
        """One account reading of one agent: one weekly window that many hours from its reset, with hours_left
        negative for a reset that has passed and None for a window the account gave no reset time for. `age` is how
        old the reading is, and `windows` replaces the one window with the windows the account actually reported."""
        hub.q("INSERT INTO agent_usage(name,data) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET data=excluded.data",
              (agent, json.dumps({"tokens": None, "limits": {
                  "collected_at": hub.now() - age, "source": "test", "plan": "max", "account_key": key,
                  "error": None,
                  "windows": windows if windows is not None else
                  [{"id": "w", "label": "7 days", "used_percent": used,
                    "resets_at": None if hours_left is None else hub.now() + hours_left * 3600,
                    "window_minutes": minutes}]}})))

    def hold(self, agent, hours_left=31):
        """The hub's own usage-limit hold on one agent: written only when a session was actually refused and its
        helper reported it, which is the thing the reading cannot tell us."""
        hub.q("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES(?,?,?,1)",
              (agent, hub.now(), hub.now() + hours_left * 3600))

    def kinds(self):
        return [w["kind"] for w in self.health()["warnings"]]

    def test_an_allowance_that_runs_out_before_it_resets_reaches_the_owner_while_he_can_act(self):
        """The readings were in the hub all along -- used_percent and resets_at per window -- and nothing read them
        until a session had already been held. His live manager on 20 October 2026: 92% of its weekly window with
        42 hours to go, and neither the manager nor the owner was told."""
        self.allowance("manager", 92, 42.7)
        warnings = {w["kind"]: w for w in self.health()["warnings"]}
        self.assertIn("allowance_pace", warnings)
        w = warnings["allowance_pace"]
        # T-37: in his words, with the time in the fleet's own zone; its reset is 42 hours off, so it has its day
        reset = hub.now() + 42.7 * 3600
        self.assertEqual(w["detail"], f"92% of its 7-day limit is used; it runs out before {hub.owner_clock(reset)}.")
        self.assertRegex(w["detail"], r"before [A-Z][a-z]+day \d\d:\d\d\.$")
        self.assertLessEqual(len(w["detail"].split()), 13)
        self.assertEqual(w["fix"], "Keep your own sessions off this account until it resets.")
        self.assertEqual(w["agent"], "manager")                 # so the app can draw a button to its page
        # One line per provider account and not per agent: the allowance belongs to the account, and the agents
        # that share one are named in that one line.
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "claude", "machine": "vps", "can": ["shell"]}
        hub.TEAM["addresses"]["vps"] = "127.0.0.3"
        self.allowance("vps", 92, 42.7)
        lines = [x for x in self.health()["warnings"] if x["kind"] == "allowance_pace"]
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0]["detail"].startswith("Manager and Vps: 92% of their 7-day limit is used; "),
                        lines[0]["detail"])

    def test_the_owner_is_told_nothing_about_an_allowance_he_can_do_nothing_about(self):
        self.allowance("manager", 40, 100)                      # a slow week recovers
        self.assertNotIn("allowance_pace", self.kinds())
        self.allowance("manager", 92, 1)                         # nearly reset: 92% is almost a full window
        self.assertNotIn("allowance_pace", self.kinds())
        self.allowance("manager", 99, 2, minutes=300)            # a five-hour window resets itself
        self.assertNotIn("allowance_pace", self.kinds())

    def test_a_week_that_reads_as_spent_says_so_before_any_session_has_been_refused(self):
        """The gap he found himself, 21 October 2026: "manager is NOT at 97% - not updated! it is concerning". His
        manager's weekly window read 100% with the reset 31 hours off, its hold was null because no session had
        been refused yet, and /ui/health answered ok with no warnings at all. The reading and the hold do not
        arrive together, and the warning that existed stood aside for a hold that was not there."""
        self.allowance("manager", 100, 31.5)        # his 31 hours, clear of the hour boundary this test rounds to
        warnings = {w["kind"]: w for w in self.health()["warnings"]}
        self.assertIn("allowance_spent", warnings)
        self.assertNotIn("allowance_pace", warnings)             # one state, said once, and never two voices
        w = warnings["allowance_spent"]
        # The reset says how far off it is, not a clock: a clock carries no date, so "at 14:00" for a reset 31 hours
        # away reads as this afternoon, and whether to wait or sign in elsewhere turns on that day. Nothing is left,
        # so there is nothing to project.
        self.assertEqual(w["detail"], "All of its 7-day limit is used; it resets in 31 hours.")
        # The manager's way out, minus the one that no longer helps: keeping sessions off the login saves what is
        # left of a window, and this one has nothing left.
        self.assertEqual(w["fix"], "Sign Manager in to another account.")
        self.assertEqual(w["agent"], "manager")
        # A worker's spent week leads to that worker, and its way out is the manager, as the pace line's is.
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}
        hub.TEAM["addresses"]["vps"] = "127.0.0.3"
        self.allowance("vps", 100, 31.5, key="openai:" + "a" * 32)
        worker = next(x for x in self.health()["warnings"]
                      if x["kind"] == "allowance_spent" and x["agent"] == "vps")
        self.assertEqual(worker["detail"], "All of its 7-day limit is used; it resets in 31 hours.")
        self.assertEqual(worker["fix"], "Tell Manager what must not wait.")

    def test_one_hour_or_one_minute_is_said_in_the_singular(self):
        """Review A11: a spent window that resets 1.5 to 2 hours away said "it resets in 1 hours"."""
        self.allowance("manager", 100, 1.6)
        w = next(x for x in self.health()["warnings"] if x["kind"] == "allowance_spent")
        self.assertEqual(w["detail"], "All of its 7-day limit is used; it resets in 1 hour.")
        self.allowance("manager", 100, 1.5 / 60)            # 90 seconds
        w = next(x for x in self.health()["warnings"] if x["kind"] == "allowance_spent")
        self.assertEqual(w["detail"], "All of its 7-day limit is used; it resets in 1 minute.")

    def test_an_agent_with_a_hyphen_is_named_as_the_apps_name_it(self):
        """Review A9: the apps show "acme-dev" as "Acme-Dev" (Swift's capitalized), and the hub wrote "Acme-dev"."""
        hub.TEAM["agents"]["acme-dev"] = {"role": "worker", "runtime": "claude", "machine": "hub", "can": ["shell"]}
        self.allowance("manager", 92, 42.7)
        self.allowance("acme-dev", 92, 42.7)                 # one account, two agents: both named first
        w = next(x for x in self.health()["warnings"] if x["kind"] == "allowance_pace")
        self.assertTrue(w["detail"].startswith("Acme-Dev and Manager: ") or
                        w["detail"].startswith("Manager and Acme-Dev: "), w["detail"])
        self.assertEqual(hub.silent_words("acme-dev", None), "Acme-Dev has never answered")

    def test_once_the_hold_is_there_the_banner_carries_it_and_this_falls_silent(self):
        """The author's rule, and it is right: while an agent is held the owner has his banner and the agent its own
        start text, and a third voice saying the same thing is noise. So this covers the span before the hold and
        hands over the moment the hold exists."""
        self.allowance("manager", 100, 31)
        self.assertIn("allowance_spent", self.kinds())
        self.hold("manager")
        self.assertNotIn("allowance_spent", self.kinds())
        # And it is the hold that silences it, not the hold's own banner: the banner is written by the tick, and
        # this answer must not depend on a tick having run.
        self.assertNotIn("manager_limited", self.kinds())
        # A hold on a worker silences that worker's account only.
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}
        hub.TEAM["addresses"]["vps"] = "127.0.0.3"
        self.allowance("vps", 100, 31, key="openai:" + "a" * 32)
        self.assertEqual(self.kinds().count("allowance_spent"), 1)
        self.hold("vps")
        self.assertNotIn("allowance_spent", self.kinds())

    def test_a_reading_the_hub_cannot_trust_and_a_window_nobody_reported_stay_silent(self):
        """100% from a reading an hour old is not a fact, and a window the account does not report is not a window
        at zero. His Studio reports no weekly window at all; it must not come out as a week at 0% or as a week at
        all, because the product never knew it."""
        self.allowance("manager", 100, 31, age=4000)             # older than USAGE_STALE: awaiting a new reading
        self.assertNotIn("allowance_spent", self.kinds())
        self.allowance("manager", 100, -2)                       # that window has reset; this reading is behind it
        self.assertNotIn("allowance_spent", self.kinds())
        self.allowance("manager", 100, 2, minutes=300)           # a five-hour window resets itself
        self.assertNotIn("allowance_spent", self.kinds())
        # The Studio's own reading, 21 October 2026: a five-hour window with no reset time and a Fable week, and no
        # weekly window of its own anywhere in it.
        self.allowance("manager", 0, None, windows=[
            {"id": "s", "label": "5 hours", "used_percent": 0, "resets_at": None, "window_minutes": 300},
            {"id": "f", "label": "7 days (Fable)", "used_percent": 0,
             "resets_at": hub.now() + 55 * 3600, "window_minutes": 10080}])
        self.assertNotIn("allowance_spent", self.kinds())
        self.assertNotIn("allowance_pace", self.kinds())
        # A window the account gave no reset time for is still spent when it says it is spent, and the line invents
        # no reset.
        self.allowance("manager", 100, None)
        spent = next(x for x in self.health()["warnings"] if x["kind"] == "allowance_spent")
        self.assertEqual(spent["detail"], "All of its 7-day limit is used.")

    def test_an_allowance_warning_about_a_worker_leads_to_that_worker_and_says_the_fleet_goes_on(self):
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}
        hub.TEAM["addresses"]["vps"] = "127.0.0.3"
        self.allowance("vps", 96, 30.5, key="openai:" + "a" * 32)
        w = next(x for x in self.health()["warnings"] if x["kind"] == "allowance_pace")
        self.assertEqual(w["agent"], "vps")
        self.assertEqual(w["detail"], "96% of its 7-day limit is used; it resets in 30 hours.")
        self.assertEqual(w["fix"], "Tell Manager what must not wait.")

    def test_the_words_are_his_and_few(self):
        """T-37, the owner's System status: "What to do" held about 246 words, "The owner has no confirmed backup
        of the hub database.", internal words ("helper", "UTC", a provider's quoted window name) and a sentence of
        36 words. Each warning of that screen now says one fact in his voice, in about 70 words for the screen."""
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}
        hub.TEAM["addresses"]["vps"] = "127.0.0.3"
        hub.touch("vps")
        hub.q("UPDATE agents SET last_seen=? WHERE name='vps'", (hub.now() - 3600,))    # silent for an hour
        # 92% of a week with 15 hours to go runs out before the reset; the provider's own name of the window is
        # "codex / 7 days", which his screen showed in quotes
        self.allowance("vps", 92, 15, key="openai:" + "a" * 32, windows=[
            {"id": "w", "label": "codex / 7 days", "used_percent": 92, "resets_at": hub.now() + 15 * 3600,
             "window_minutes": 10080}])
        with unittest.mock.patch.object(hub, "STARTED", hub.now() - 7200):    # a hub that has heard it go quiet
            warnings = self.health()["warnings"]
        said = [(w["kind"], w["detail"], w["fix"]) for w in warnings
                if w["kind"] in ("backup_missing", "helper_offline", "machine_stale", "allowance_pace")]
        self.assertEqual(sorted({k for k, _d, _f in said}),
                         ["allowance_pace", "backup_missing", "helper_offline", "machine_stale"])
        words = " ".join(d + " " + (f or "") for _k, d, f in said)
        for wrong in ("owner", "UTC", "helper", '"', "Fleet", "allowance"):
            self.assertNotIn(wrong, words)
        for sentence in re.split(r"(?<=[.;])\s+", words.strip()):
            self.assertLessEqual(len(sentence.split()), 16, sentence)
        self.assertRegex(next(d for k, d, _f in said if k == "helper_offline" and "since" in d and ":" in d),
                         r"^Silent since \d\d:\d\d\.$")
        self.assertLessEqual(len(words.split()), 70)

    def test_a_server_that_is_behind_or_whose_update_failed_is_said_without_a_revision(self):
        """T-37: the app's title says "Vps is behind" or "The update of Vps failed" and its button "Update Vps", so
        the line is the one fact behind them, with no revision hash and no second way on."""
        hub.TEAM["addresses"]["vps"] = "127.0.0.3"
        hub.TEAM["agents"]["vps"] = {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"]}
        hub.touch("vps")
        self.vault_report("vps", None)                  # it reports revision b…, and the hub serves d…
        with unittest.mock.patch.object(hub, "kit_revision", return_value="d" * 40):
            behind = next(w for w in self.health()["warnings"] if w["kind"] == "machine_behind")
            hub.q("UPDATE machine_updates SET state='failed' WHERE agent='vps'")
            failed = next(w for w in self.health()["warnings"] if w["kind"] == "machine_failed")
        self.assertEqual((behind["detail"], behind["fix"], behind["agent"]),
                         ("It runs an older version than the hub.", None, "vps"))
        self.assertEqual((failed["detail"], failed["fix"], failed["agent"]),
                         ("It still runs the version it had.", None, "vps"))

    def vault_report(self, agent, source, reported=None, revision="b" * 40):
        """One machine report of an agent whose machine has a vault broker that says what its program hashes to."""
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES(?,?,?) "
              "ON CONFLICT(agent) DO UPDATE SET data=excluded.data, reported=excluded.reported",
              (agent, json.dumps({"revision": revision, "access": {"user": "fleet"},
                                  "security": {"vault": {"mode": "broker", "isolated": True,
                                                         "broker_source": source, "broker_read_at": hub.now()}}}),
               reported if reported is not None else hub.now()))
        hub.q("INSERT INTO machine_updates(agent,state,requested,desired) VALUES(?,'current',?,?) "
              "ON CONFLICT(agent) DO UPDATE SET state='current'", (agent, hub.now(), revision))

    REVISION = "b" * 40             # the revision this hub serves and every machine of these tests reports

    def vault_warnings(self, want="a" * 64):
        """The vault warnings of a hub that can read its revision and its own vault.py. These tests have no git
        checkout of their own, so both are stood in for; test_machines proves them against a real repository."""
        with unittest.mock.patch.object(hub, "vault_source", return_value=want), \
                unittest.mock.patch.object(hub, "kit_revision", return_value=self.REVISION):
            return [w for w in self.health()["warnings"] if w["kind"] == "vault_behind"]

    def test_a_vault_broker_that_a_release_never_reached_is_said_once_for_its_machine(self):
        """The vault broker runs a root-owned copy of vault.py that no release reinstalls, and lifecycle.OWNER_ONLY
        lets a commit that changes only that file advance the revision a machine reports. So the machine says
        "current" while its broker runs the copy installed by hand, and the broker's own checksum is the only thing
        that says so. One warning for each machine, because one broker serves all of its agents."""
        hub.TEAM["addresses"]["vps"] = "127.0.0.3"
        for name in ("vps", "vps-lead"):
            hub.TEAM["agents"][name] = {"role": "worker", "runtime": "codex", "machine": "vps", "can": ["shell"],
                                        "vault": "broker"}
        hub.q("INSERT INTO machine_updates(agent,state,requested,desired) VALUES('manager','current',?,?)",
              (hub.now(), "b" * 40))
        hub.q("INSERT INTO machine_status(agent,data,reported) VALUES('manager',?,?)",
              (json.dumps({"revision": "b" * 40, "security": {}}), hub.now()))
        # The broker that runs the fleet's own vault.py says nothing is wrong.
        self.vault_report("vps", "a" * 64)
        self.vault_report("vps-lead", "a" * 64)
        self.assertEqual(self.vault_warnings(), [])
        # One that runs another copy is one warning, for the machine and not for each of its agents.
        self.vault_report("vps", "c" * 64)
        self.vault_report("vps-lead", "c" * 64)
        behind = self.vault_warnings()
        self.assertEqual(len(behind), 1)
        self.assertIn("vps", behind[0]["detail"])
        self.assertIn(behind[0]["agent"], ("vps", "vps-lead"))
        # The machine brings its own broker onto a release, so a warning that stays means it could not. T-37: he
        # reads which server and the one way on, in a few words: no revision, no path and no command. The steps by
        # hand are WORKER-INSTALL.md's ("When a release changes vault.py"), for whoever he tells.
        self.assertEqual(behind[0]["detail"], "The vault on vps has not taken the last update.")
        self.assertEqual(behind[0]["fix"], "It updates itself within ten minutes; tell us if it does not.")
        said = behind[0]["detail"] + " " + behind[0]["fix"]
        for wrong in ("/", "`", "vault.py", "hubsetup", "journalctl", "root", "c" * 12, "b" * 12):
            self.assertNotIn(wrong, said)
        # A broker that says nothing about its program raises nothing: a Mac's signed helper, which the app updates
        # itself, and a broker older than this one. Unknown is not behind.
        self.vault_report("vps", None)
        self.vault_report("vps-lead", None)
        self.assertEqual(self.vault_warnings(), [])
        # Nor does the hub guess when it cannot read its own vault.py.
        self.vault_report("vps", "c" * 64)
        self.vault_report("vps-lead", "c" * 64)
        self.assertEqual(len(self.vault_warnings()), 1)
        self.assertEqual(self.vault_warnings(want=None), [])
        # A machine that has not taken the release at all raises its own warning and not this one too: two lines
        # for one cause say less than one.
        hub.q("UPDATE machine_updates SET state='behind' WHERE agent='vps'")
        hub.q("UPDATE machine_status SET data=? WHERE agent='vps'",
              (json.dumps({"revision": "d" * 40, "access": {"user": "fleet"},
                           "security": {"vault": {"mode": "broker", "broker_source": "c" * 64,
                                                  "broker_read_at": hub.now()}}}),))
        self.assertEqual(self.vault_warnings(), [])
        hub.q("UPDATE machine_updates SET state='current' WHERE agent='vps'")
        hub.q("UPDATE machine_status SET reported=? WHERE agent='vps'", (hub.now() - hub.MACHINE_STALE - 1,))
        self.assertEqual(self.vault_warnings(), [])

    def test_the_integrity_check_runs_and_reports(self):
        hub.integrity_check(hub.now())
        self.assertEqual(self.health()["hub"]["integrity"]["result"], "ok")
        hub.kv_set("integrity", "row 3 missing from index")
        self.assertIn("integrity", [w["kind"] for w in self.health()["warnings"]])

    # ---- a task that nothing is moving (tasks_stuck), and the hub's own heartbeat (tick_heartbeat)

    def worker(self, name="studio", address="127.0.0.4", online=True):
        hub.TEAM["agents"][name] = {"role": "worker", "runtime": "claude", "machine": name, "can": ["shell"]}
        hub.TEAM["addresses"][name] = address
        if online:
            hub.touch(name)             # its helper is checking in
        return name

    def task(self, **cols):
        cols = dict({"title": "Build the thing", "owner": "studio", "requester": "manager", "state": "working",
                     "created": hub.now(), "attempt": 1, "nudge_level": 2}, **cols)
        return hub.ins(f"INSERT INTO tasks({','.join(cols)}) VALUES({','.join('?' * len(cols))})",
                       tuple(cols.values()))

    def told(self, tid, at, agent="manager", filed=None):
        """The notice about a stuck task, as the hub sends it to its requester (stuck_told)."""
        eid = hub.ins("INSERT INTO events(agent,kind,task,text,created,extra) VALUES(?,'say',?,?,?,'{}')",
                      (agent, filed if filed is not None else tid, f"[hub] T-{tid} is stuck.", at))
        hub.stuck_told(tid, eid)
        return eid

    def stuck(self):
        return [w for w in self.health()["warnings"] if w["kind"] == "tasks_stuck"]

    def test_a_task_that_nothing_is_moving_reaches_the_owners_screen(self):
        """Plan C10: no clock. Every alarm about one task goes to its requester once, and the owner sees the task
        only while that requester had a turn after the notice and left it unread: then nobody is acting on it."""
        self.worker()
        t0 = hub.now()
        gone = self.task(stalled_since=t0 - 2 * 3600, stalled_reason="its session is not running")
        self.assertEqual(self.stuck(), [])                  # nobody was told
        notice = self.told(gone, t0 - 60)
        self.assertEqual(self.stuck(), [])                  # told, and the manager has had no turn since
        hub.kv_set("turn_ended:manager", t0 - 30)
        w, = self.stuck()
        # T-37: how many and that nobody acts on them, and the one way on; the task itself is the manager's to read
        self.assertEqual((w["detail"], w["fix"]), ("1 task is stuck, and nobody is acting on it.",
                                                   "Tell Manager what to do with it."))
        self.assertIn(f"T-{gone} (Build the thing, owner studio) has no live path and is still working: its session "
                      f"is not running", " ".join(line for _, line in hub.tasks_stuck(hub.now())))
        self.assertEqual(w["agent"], "manager")             # so the app can draw a button to its page
        hub.q("UPDATE events SET read_at=? WHERE id=?", (t0, notice))
        self.assertEqual(self.stuck(), [])                  # it read it: the decision is its own
        # Two more kinds, the oldest notice first: two empty turns (plan C9), and losses that stopped its restarts.
        wedged = self.task(live_path="live session", nudged_at=t0 - 3 * 3600)
        self.told(wedged, t0 - 3 * 3600)
        lost = self.task(live_path="live session", restarts=hub.LOST_IN_A_ROW, nudge_level=0)
        self.told(lost, t0 - 600)
        w, = self.stuck()
        self.assertEqual(w["detail"], "2 tasks are stuck, and nobody is acting on them.")
        lines = " ".join(line for _, line in hub.tasks_stuck(hub.now()))      # the manager's to read
        self.assertIn(f"T-{wedged} (Build the thing, owner studio) ended two turns in a row with nothing waiting "
                      f"for it", lines)
        self.assertIn(f"T-{lost} (Build the thing, owner studio) lost its session again and again", lines)
        self.assertLess(lines.index(f"T-{wedged}"), lines.index(f"T-{lost}"))

    def test_the_owner_is_told_nothing_about_a_task_that_is_quiet_on_purpose(self):
        """The case that must not regress. Three kinds of task are quiet because something said so, and none of
        them is stuck: one that the owner or the manager held, one whose agent is at its usage limit, and one parked
        until the time its own agent named. A session inside one long call ends no turn, so nothing tells anybody
        that it is stuck."""
        t0 = hub.now()
        # One agent each, so that no task is quiet for another task's reason and each is proved alone.
        for i, name in enumerate(("studio", "vps", "mini", "box")):
            self.worker(name, address="127.0.0." + str(10 + i))
        held = self.task(owner="studio", live_path="paused by the owner")
        hub.q("INSERT INTO holds(task,kind,by,state,created,attempt) VALUES(?,'pause','owner','confirmed',?,1)",
              (held, t0 - 3 * 3600))
        limited = self.task(owner="vps", live_path="waiting for vps's usage limit to reset")
        hub.q("INSERT INTO agent_limits(agent,since,until,reset_known) VALUES('vps',?,?,1)", (t0 - 3 * 3600, t0 + 3600))
        parked = self.task(owner="mini", live_path="waiting until tomorrow, as mini asked")
        hub.q("INSERT INTO reminders(due,note,agent,task,created) VALUES(?,'the build',?,?,?)",
              (t0 + 7200, "mini", parked, t0 - 3 * 3600))
        busy = self.task(owner="box", live_path="live session", nudge_level=0)
        for tid in (held, limited, parked):
            self.told(tid, t0 - 3 * 3600)
        hub.kv_set("turn_ended:manager", t0)
        self.assertEqual(self.stuck(), [])
        # Each of the three is quiet for its own reason: take that one reason away and its line appears.
        hub.q("UPDATE holds SET state='released' WHERE task=?", (held,))
        hub.q("UPDATE agent_limits SET ended=? WHERE agent='vps'", (t0 - 3 * 3600,))
        hub.q("UPDATE reminders SET done=1 WHERE task=?", (parked,))
        lines = " ".join(line for _, line in hub.tasks_stuck(hub.now()))
        for tid in (held, limited, parked):
            self.assertIn(f"T-{tid}", lines)
        self.assertNotIn(f"T-{busy}", lines)
        self.assertEqual("3 tasks are stuck, and nobody is acting on them.", self.stuck()[0]["detail"])

    def test_a_task_whose_requester_was_not_told_or_had_no_turn_since_is_not_the_owners_to_see(self):
        """The owner is told only what the manager (or a lead) already had in front of it and did not settle. A lead
        is measured by the turns of its own task's session, where its notice is filed, and what it leaves unread goes
        to the manager before the owner sees it."""
        self.worker()
        t0 = hub.now()
        tid = self.task(stalled_since=t0 - 2 * 3600, stalled_reason="its session is not running")
        hub.kv_set("turn_ended:manager", t0)
        self.assertEqual(self.stuck(), [])                  # never told: the hub is still starting it again
        self.told(tid, t0 + 1)
        self.assertEqual(self.stuck(), [])                  # told after the manager's last turn
        hub.TEAM["agents"]["lead"] = {"role": "lead", "runtime": "claude", "machine": "studio", "can": ["shell"]}
        parent = self.task(owner="lead", live_path="live session", nudge_level=0)
        hub.q("INSERT INTO attempts(task,attempt,created,reason) VALUES(?,1,?,'created')", (parent, t0))
        sub = self.task(requester="lead", parent=parent, stalled_reason="its session is not running")
        self.told(sub, t0 + 1, agent="lead", filed=parent)
        self.assertNotIn(f"T-{sub}", " ".join(line for _, line in hub.tasks_stuck(hub.now())))
        hub.q("UPDATE attempts SET turn=? WHERE task=?", (json.dumps({"session": "s", "seq": 4, "turns": 1,
                                                                      "running": False, "how": "end_turn",
                                                                      "at": t0 + 2, "calls": {}, "said": None}),
                                                          parent))
        # The owner, 29 October 2026: what a lead leaves unread goes to the manager first, and reaches his screen
        # only when the manager had a turn after that and left it unread too (lead_unread_sweep).
        self.assertNotIn(f"T-{sub}", " ".join(line for _, line in hub.tasks_stuck(hub.now())))
        hub.lead_unread_sweep(hub.now())
        told = hub.q1("SELECT text FROM events WHERE agent='manager' ORDER BY id DESC LIMIT 1")["text"]
        self.assertIn(f"T-{sub} (Build the thing, owner studio): lead was told that it is stuck", told)
        self.assertNotIn(f"T-{sub}", " ".join(line for _, line in hub.tasks_stuck(hub.now())))
        hub.kv_set("turn_ended:manager", hub.now() + 1)
        self.assertIn(f"T-{sub}", " ".join(line for _, line in hub.tasks_stuck(hub.now())))

    def test_the_hub_says_when_its_own_timers_stopped(self):
        """The sweeper's own sweeper. In the review's S13 one raising callee ended the whole pass every five seconds,
        and the journal was the only record: 20 minutes with a dead session not restarted, no nudge and no warning
        anywhere. Each step runs on its own now, and a step that restarts work and raises holds this up."""
        hub.TEAM["hub"] = {"machine": "hub", "port": 8765}
        self.assertNotIn("timers_stalled", [w["kind"] for w in self.health()["warnings"]])    # nothing has ticked here
        hub.kv_set("tick_ok", hub.now() - 5)
        self.assertNotIn("timers_stalled", [w["kind"] for w in self.health()["warnings"]])
        hub.kv_set("tick_ok", hub.now() - 20 * 60)
        w = next(x for x in self.health()["warnings"] if x["kind"] == "timers_stalled")
        # T-37: since when and what it costs him, and the one way on, with no command
        self.assertEqual(w["detail"], f"Since {hub.owner_clock(hub.now() - 20 * 60)}, no stuck task or session is "
                                      f"restarted.")
        self.assertEqual(w["fix"], "Restart the hub's server, and tell us if this comes back.")
        self.assertEqual(w["agent"], "manager")             # the agent on the hub's own machine
        # A record that is not a time says nothing, rather than taking the whole screen down with it.
        hub.kv_set("tick_ok", "the hub was here")
        self.assertNotIn("timers_stalled", [w["kind"] for w in self.health()["warnings"]])

    def test_a_complete_pass_of_the_timers_records_itself_and_a_broken_one_does_not(self):
        with unittest.mock.patch.dict(hub.CFG, {"silence": 180, "question_wait": 120, "manager_silence": 120,
                                                "stop_after": 60, "offline_after": 90, "tick": 5}):
            hub.tick()
            first = float(hub.kv_get("tick_ok"))
            self.assertAlmostEqual(first, hub.now(), delta=10)
            # A step that raises stops only itself: every step after it still runs, the restarts too, and so the
            # heartbeat moves. Before, this one bad row ended the pass at chat_sweep, every five seconds.
            ran = []
            with unittest.mock.patch.object(hub, "chat_sweep", side_effect=RuntimeError("a bad row")), \
                    unittest.mock.patch.object(hub, "restart_sweep", side_effect=ran.append), \
                    unittest.mock.patch.object(hub, "trigger_sweep", side_effect=ran.append), \
                    unittest.mock.patch.object(hub.traceback, "print_exc"):
                hub.tick()
            self.assertEqual(len(ran), 2)
            second = float(hub.kv_get("tick_ok"))
            self.assertGreaterEqual(second, first)
            # A step that restarts work and raises holds the heartbeat, so the warning above is what the owner reads,
            # and what it says is then true: no stuck task or session is restarted. This is S13: nothing else says it.
            with unittest.mock.patch.object(hub, "restart_sweep", side_effect=RuntimeError("a bad row")), \
                    unittest.mock.patch.object(hub, "trigger_sweep", side_effect=ran.append), \
                    unittest.mock.patch.object(hub.traceback, "print_exc"):
                hub.tick()
            self.assertEqual(len(ran), 3)              # the rest of the pass ran
            self.assertEqual(float(hub.kv_get("tick_ok")), second)


if __name__ == "__main__":
    unittest.main()

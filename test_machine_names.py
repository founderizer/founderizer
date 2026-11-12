"""A server's name in Fleet is its name in Tailscale (the owner, 30 October 2026: "can't we always use the actual
machine names?"). The join takes it; a rename in Tailscale renames the machine in Fleet by itself, two reads after it,
in team.json and in every record; a renamed server is known by its address and key and takes its new name once its
checkout has it; a hub that stops between the commit and the records finishes the rename; a restore stands the copy's
hub machine on this one. Against a local hub with a temporary Fleet repository, as test_servers."""
import json
import unittest
from unittest.mock import patch

import hub
from test_servers import HUB, KEY, NEW, OTHER, OWNER, VPS, ServerService, Servers, git, sha, tailnet_status


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (Follow, Join, Columns, Restore, Adopt) for name in cls.__dict__
                              if name.startswith("test_"))


class Names(Servers):
    """mini is a Mac server at NEW whose service reads, with the feature that takes a new name."""

    def setUp(self):
        super().setUp()
        hub.MACHINE_NAMES.update(names={}, waits={}, seen=None, asked=0.0, origin_at=0.0)
        self.joined("mini", "mac")
        self.fresh("mini")

    def fresh(self, server, source=NEW, features=(hub.NAMES_FEATURE,)):
        status, answer = self.service(f"/server/{server}/status", {
            "revision": hub.kit_revision(fresh=True), "os": {"name": "macOS 15.6"},
            "runtimes": {"codex": {"version": None, "signed_in": None}, "claude": {"version": "2.1", "signed_in": True}},
            "access": {"user": "dana"}, "features": list(features)}, source=source)
        self.assertEqual(status, 200, answer)
        return answer

    def read_twice(self, t0=None):
        """Two reads of the machines' names in Tailscale, as the sweep makes them: a rename needs the same name twice."""
        t0 = t0 or hub.now()
        with hub.LOCK:
            hub.follow_tailnet_names(tailnet_status(self.tailnet), t0)
            hub.follow_tailnet_names(tailnet_status(self.tailnet), t0)

    def said(self, agent="manager"):
        return [r["text"] for r in hub.q("SELECT text FROM events WHERE agent=? AND kind='say' ORDER BY id", (agent,))]

    def tearDown(self):
        hub.MACHINE_NAMES.update(names={}, waits={}, seen=None, asked=0.0, origin_at=0.0)
        super().tearDown()


class Follow(Names):
    def test_the_sweep_reads_tailscale_by_itself_and_renames_at_its_second_read(self):
        self.tailnet[NEW] = "danas-mini"
        t0 = hub.now()
        with hub.LOCK:
            thread = hub.machine_names_sweep(t0)
        thread.join(5)
        with hub.LOCK:
            self.assertIsNone(hub.machine_names_sweep(t0 + 1))           # it follows the read, and asks no other
        self.assertIn("mini", self.origin_team()["addresses"])
        hub.MACHINE_NAMES["asked"] -= hub.MACHINE_NAMES_EVERY          # 10 minutes later, for the sweep
        with hub.LOCK:
            hub.machine_names_sweep(t0 + 2).join(5)
            hub.machine_names_sweep(t0 + 3)
        self.assertIn("danas-mini", self.origin_team()["addresses"])
        self.assertEqual(hub.TAILNET_NAMES["names"], ("hub.tail0000.ts.net", "hub"))

    def test_a_server_renamed_in_tailscale_is_renamed_in_fleet_everywhere(self):
        hub.q("INSERT INTO deposits(login,machine,agent,recipient,sha256,request_id,created,finished) "
              "VALUES('bws://x','mini','scout','age1x','0',?,?,?)", ("r1", hub.now(), hub.now()))
        team = self.origin_team()
        team["vault_stores"] = {"mini": "age1" + "q" * 58}
        (self.kit / "team.json").write_text(json.dumps(team, indent=2) + "\n")
        git("commit", "-qam", "the vault of mini", cwd=self.kit)
        git("push", "-q", "origin", "HEAD", cwd=self.kit)
        hub._revision_cache.update(at=0.0, value=None)
        hub.TEAM = team
        self.tailnet[NEW] = "danas-mini"
        with hub.LOCK:
            hub.follow_tailnet_names(tailnet_status(self.tailnet), hub.now())
        self.assertIn("mini", self.origin_team()["addresses"])           # one read is not enough
        self.read_twice()
        team = self.origin_team()
        self.assertEqual(team["addresses"]["danas-mini"], NEW)
        self.assertNotIn("mini", team["addresses"])
        self.assertEqual(team["servers"]["danas-mini"], {"kind": "mac", "user": "dana"})
        self.assertEqual(team["vault_stores"], {"danas-mini": "age1" + "q" * 58})
        self.assertEqual(list(team["addresses"])[-1], "danas-mini")       # in its own place
        self.assertEqual(hub.TEAM["addresses"]["danas-mini"], NEW)
        for table, column in hub.MACHINE_COLUMNS:
            self.assertIsNone(hub.q1(f"SELECT 1 FROM {table} WHERE {column}='mini'"), table)
        self.assertEqual(hub.q1("SELECT sha256 FROM server_keys WHERE server='danas-mini'")["sha256"], sha(KEY))
        self.assertIsNotNone(hub.q1("SELECT 1 FROM server_status WHERE server='danas-mini'"))
        self.assertEqual(hub.q1("SELECT machine FROM deposits")["machine"], "danas-mini")
        self.assertIsNone(hub.kv_get("machine_rename"))
        self.assertIn("[hub] The server mini is now called danas-mini, its name in Tailscale. Use danas-mini from now "
                      "on.", self.said())
        view, servers = self.servers()
        self.assertEqual(sorted(servers), ["danas-mini", "hub", "mac-studio", "vps"])
        self.assertEqual(view["join"]["server"], "danas-mini")           # the code finds its server by address

    def test_the_hub_machine_takes_its_name_too_with_its_agents_and_access(self):
        self.tailnet[HUB] = "worker-2"
        self.read_twice()
        team = self.origin_team()
        self.assertEqual(team["hub"]["machine"], "worker-2")
        self.assertEqual(team["agents"]["manager"]["machine"], "worker-2")
        self.assertEqual(hub.hub_address(), (HUB, 8765))
        _, servers = self.servers()
        self.assertTrue(servers["worker-2"]["hub"])
        self.tailnet[VPS] = "worker-1"                                 # vps has an agent and SSH access
        self.read_twice()
        team = self.origin_team()
        self.assertEqual((team["agents"]["vps"]["machine"], team["agents"]["lead"]["machine"]), ("worker-1",) * 2)
        self.assertIn("worker-1", team["access"])
        self.assertNotIn("vps", team["access"])

    def test_a_rename_that_must_wait_waits_and_says_why_once(self):
        self.tailnet[NEW] = "9-lives"                                   # no name a server can have
        self.read_twice()
        self.read_twice()
        self.assertIn("mini", self.origin_team()["addresses"])
        hub.MACHINE_NAMES.update(waits={}, names={})                    # a restart forgets what it read
        self.read_twice()
        told = [t for t in self.said() if "9-lives" in t]
        self.assertEqual(len(told), 1, told)                            # a lasting reason, told once, a restart too
        self.tailnet[NEW] = "vps"                                       # another server's name
        self.read_twice()
        self.assertIn("the fleet has a server named vps", self.said()[-1])
        self.tailnet[NEW] = "danas-mini"
        before = len(self.said())
        with patch.object(hub, "central_ok", lambda t0=None: True):    # the central vault pins vaults by name
            self.read_twice()
        self.assertIn("mini", self.origin_team()["addresses"])
        self.assertEqual(len(self.said()), before)                      # logged only: nobody can end it
        hub.q("INSERT INTO deposits(login,machine,agent,recipient,sha256,request_id,created) "
              "VALUES('bws://x','mini','scout','age1x','0','r1',?)", (hub.now(),))
        self.read_twice()
        self.assertIn("mini", self.origin_team()["addresses"])
        hub.q("UPDATE deposits SET finished=?", (hub.now(),))
        hub.q("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) "
              "VALUES('mini','install','scout','claude','running',?,?)", (hub.now(), hub.now()))
        self.read_twice()
        self.assertIn("mini", self.origin_team()["addresses"])
        self.assertEqual(len(self.said()), before)                      # a job ends by itself: no word
        hub.q("UPDATE server_jobs SET state='done'")
        hub.q("UPDATE server_status SET reported=? WHERE server='mini'", (hub.now() - hub.MACHINE_STALE - 1,))
        self.read_twice()                                               # a service that is off
        self.assertIn("mini", self.origin_team()["addresses"])
        self.fresh("mini", features=())                                 # a service older than this release
        self.read_twice()
        self.assertIn("mini", self.origin_team()["addresses"])
        self.fresh("mini")
        self.read_twice()
        self.assertIn("danas-mini", self.origin_team()["addresses"])

    def test_a_server_key_holds_its_name_as_team_json_does(self):
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('worker-9','0',1)")
        self.tailnet[NEW] = "worker-9"
        self.read_twice()
        self.assertIn("mini", self.origin_team()["addresses"])
        self.assertIn("the fleet has a server named worker-9", self.said()[-1])

    def test_a_removed_servers_history_does_not_hold_its_name(self):
        hub.q("INSERT INTO server_status(server,data,reported) VALUES('worker-9','{}',1)")
        hub.q("INSERT INTO server_jobs(server,kind,agent,runtime,state,created,updated) "
              "VALUES('worker-9','install','old','claude','done',1,1)")
        for machine in ("worker-9", "mini"):                            # a target that both once wrote to
            hub.q("INSERT INTO place_hosts(machine,host,port,user,line_sha256,updated) VALUES(?,'box',22,'root','0',1)",
                  (machine,))
        self.tailnet[NEW] = "worker-9"
        self.read_twice()
        self.assertIn("worker-9", self.origin_team()["addresses"])
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM server_status WHERE server='worker-9'")["n"], 1)
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM place_hosts WHERE machine='worker-9'")["n"], 1)
        self.assertEqual(hub.q1("SELECT server FROM server_keys WHERE sha256=?", (sha(KEY),))["server"], "worker-9")
        self.assertIsNone(hub.kv_get("machine_rename"))

    def test_a_renamed_server_is_known_by_its_address_and_key(self):
        self.tailnet[NEW] = "danas-mini"
        self.read_twice()
        answer = self.fresh("mini")                                    # the old name, from the server's own address
        self.assertEqual(answer["server"], "danas-mini")
        self.assertEqual(hub.q1("SELECT COUNT(*) n FROM server_status WHERE server='mini'")["n"], 0)
        self.assertEqual(self.service("/server/mini/jobs")[0], 200)
        self.assertEqual(self.service("/server/danas-mini/jobs")[0], 200)
        self.assertEqual(self.service("/server/danas-mini/jobs", source=OTHER)[0], 403)
        self.assertEqual(self.service("/server/danas-mini/jobs", key="another key")[0], 403)
        self.assertEqual(self.service("/server/danas-mini/jobs", source=VPS)[0], 403)   # vps has no server key

    def test_a_rename_that_a_stop_cut_short_is_finished(self):
        self.tailnet[NEW] = "danas-mini"
        with patch.object(hub, "rename_machine_rows", side_effect=RuntimeError("stopped")), \
                self.assertRaises(RuntimeError), hub.LOCK:
            hub.rename_machine("mini", "danas-mini", hub.now())
        self.assertIn("danas-mini", self.origin_team()["addresses"])     # the commit landed, the records did not
        self.assertEqual(hub.q1("SELECT server FROM server_keys WHERE sha256=?", (sha(KEY),))["server"], "mini")
        with hub.LOCK:
            hub.machine_names_sweep(hub.now())
        self.assertEqual(hub.q1("SELECT server FROM server_keys WHERE sha256=?", (sha(KEY),))["server"], "danas-mini")
        self.assertIsNone(hub.kv_get("machine_rename"))
        self.assertEqual(self.fresh("danas-mini")["server"], "danas-mini")

    def test_a_commit_that_did_not_land_leaves_nothing_behind(self):
        with patch.object(hub, "commit_kit_file", side_effect=hub.Refusal(409, "the ref moved")), \
                self.assertRaises(hub.Refusal), hub.LOCK:
            hub.rename_machine("mini", "danas-mini", hub.now())
        with hub.LOCK:
            hub.machine_names_sweep(hub.now())
        self.assertIsNone(hub.kv_get("machine_rename"))
        self.assertIn("mini", self.origin_team()["addresses"])
        self.assertEqual(hub.q1("SELECT server FROM server_keys WHERE sha256=?", (sha(KEY),))["server"], "mini")

    def test_a_rename_whose_commit_landed_before_the_checkout_moved_is_finished(self):
        """commit_kit_file pushes first: a stop after the push leaves origin renamed and the hub's checkout behind."""
        moved = hub.commit_kit_file

        def push_only(*args, **kwargs):
            with patch.object(hub, "git_kit", side_effect=lambda *a, **k: (1, "", "stopped") if a[:1] == ("merge",)
                              else real_git(*a, **k)):
                return moved(*args, **kwargs)
        real_git = hub.git_kit
        with patch.object(hub, "commit_kit_file", push_only), self.assertRaises(hub.Refusal), hub.LOCK:
            hub.rename_machine("mini", "danas-mini", hub.now())
        self.assertIn("danas-mini", self.origin_team()["addresses"])     # origin has it
        self.assertIn("mini", json.loads((self.kit / "team.json").read_text())["addresses"])    # the hub does not
        fetches, git_kit = [], hub.git_kit
        with patch.object(hub, "git_kit", lambda *a, **k: (fetches.append(a) if a[:1] == ("fetch",) else None,
                                                         (1, "", "no answer"))[1] if a[:1] == ("fetch",)
                          else git_kit(*a, **k)), hub.LOCK:
            hub.finish_machine_rename(hub.now())                      # origin does not answer: the note stays
            hub.finish_machine_rename(hub.now() + 5)                  # and the next tick does not ask again
        self.assertEqual(len(fetches), 1)
        self.assertIsNotNone(hub.kv_get("machine_rename"))
        hub.MACHINE_NAMES["origin_at"] = 0.0                            # ten minutes later
        with hub.LOCK:
            hub.machine_names_sweep(hub.now())
        self.assertIn("danas-mini", json.loads((self.kit / "team.json").read_text())["addresses"])
        self.assertEqual(hub.q1("SELECT server FROM server_keys WHERE sha256=?", (sha(KEY),))["server"], "danas-mini")
        self.assertIsNone(hub.kv_get("machine_rename"))
        self.assertEqual(self.fresh("mini")["server"], "danas-mini")

    def test_no_second_rename_starts_while_one_is_unfinished(self):
        """Four servers take their names in one pass on the live fleet: one rename that stopped after its push must
        not lose its note to the next."""
        self.joined("box", "linux", source=OTHER, user="fleet")
        self.fresh("box", source=OTHER)
        moved, real_git = hub.commit_kit_file, hub.git_kit

        def push_only(*args, **kwargs):
            with patch.object(hub, "git_kit", side_effect=lambda *a, **k: (1, "", "stopped") if a[:1] == ("merge",)
                              else real_git(*a, **k)):
                return moved(*args, **kwargs)
        self.tailnet.update({NEW: "danas-mini", OTHER: "worker-5"})
        with patch.object(hub, "commit_kit_file", push_only):
            self.read_twice()
        self.assertEqual(json.loads(hub.kv_get("machine_rename")), ["mini", "danas-mini"])
        self.assertIn("box", self.origin_team()["addresses"])           # not started
        with hub.LOCK:
            hub.machine_names_sweep(hub.now())                          # the first one finishes
        self.assertEqual(hub.q1("SELECT server FROM server_keys WHERE sha256=?", (sha(KEY),))["server"], "danas-mini")
        self.fresh("mini", source=NEW)
        self.fresh("box", source=OTHER)
        self.read_twice()                                               # and the next pass takes the other
        self.assertEqual({"danas-mini", "worker-5"} - set(self.origin_team()["addresses"]), set())

    def test_the_tick_runs_the_sweep(self):
        with patch.object(hub, "machine_names_sweep") as sweep:
            hub.tick()
        sweep.assert_called_once()

    def test_a_note_of_a_server_that_left_meanwhile_is_forgotten(self):
        hub.kv_set("machine_rename", json.dumps(["gone", "gone-too"]))
        with hub.LOCK:
            hub.finish_machine_rename(hub.now())
        self.assertIsNone(hub.kv_get("machine_rename"))


class Join(Names):
    def test_a_join_takes_the_machines_name_in_tailscale(self):
        answer = self.code("worker-5", "linux")
        self.assertNotIn("--hostname", answer["line"])                 # it keeps the name its provider gave it
        self.assertEqual(answer["name"], "")
        status, result = self.join(answer["code"], source=OTHER, kind="linux", user="fleet")
        self.assertEqual((status, result["server"]), (200, "worker-5"), result)
        self.assertEqual(self.origin_team()["addresses"]["worker-5"], OTHER)
        view, _ = self.servers()
        self.assertEqual((view["join"]["name"], view["join"]["server"]), ("", "worker-5"))

    def test_an_older_apps_typed_name_is_only_the_codes_label(self):
        status, answer = self.owner("/ui/servers/join", name="box", kind="linux")
        self.assertEqual((status, answer["name"]), (200, "box"))
        self.tailnet[OTHER] = "worker-5"
        self.assertEqual(self.join(answer["code"], source=OTHER, kind="linux", user="fleet")[1]["server"], "worker-5")
        view, _ = self.servers()
        self.assertEqual((view["join"]["name"], view["join"]["server"]), ("box", "worker-5"))
        self.assertNotIn("box", self.origin_team()["addresses"])

    def test_a_join_refuses_a_name_fleet_cannot_use(self):
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('old-box','0',1)")
        for name, words in (("9-lives", "Rename this server in Tailscale"), ("vps", "has a server named vps"),
                            ("owner", "Rename this server in Tailscale"), ("old-box", "has a server named old-box")):
            self.tailnet[OTHER] = name
            status, answer = self.join(self.code(name, "linux")["code"], source=OTHER, kind="linux", user="fleet")
            self.assertEqual(status, 409, name)
            self.assertIn(words, answer["error"], name)

    def test_a_join_reads_tailscale_again_only_for_a_good_code(self):
        reads = []
        status_of = hub.tailnet_status
        code = self.code("worker-5")["code"]            # making a code reads the hub's own tags (hub.join_tags)
        with patch.object(hub, "tailnet_status", lambda: reads.append(1) or status_of()):
            self.assertEqual(self.join("AAAA-BBBB-CCCC", source=OTHER)[0], 403)
            self.assertEqual(reads, [])                                 # a wrong code costs no read
            self.tailnet[OTHER] = "worker-5"
            self.assertEqual(self.join(code, source=OTHER)[0], 200)
            self.assertEqual(reads, [1])                                # the last read did not have it yet

    def test_a_join_reads_tailscale_again_when_the_last_reads_name_is_refused(self):
        code = self.code("vps", "linux")["code"]
        hub.MACHINE_NAMES["names"] = {OTHER: "vps"}                    # its name ten minutes ago
        self.tailnet[OTHER] = "worker-5"                                # renamed in Tailscale since
        status, answer = self.join(code, source=OTHER, kind="linux", user="fleet")
        self.assertEqual((status, answer.get("server")), (200, "worker-5"), answer)

    def test_a_join_without_a_name_in_tailscale(self):
        code = self.code("x")["code"]
        self.next_name = None
        with patch.object(hub, "tailnet_status", lambda: None):        # tailscale did not answer
            status, answer = self.join(code, source=OTHER)
        self.assertEqual(status, 503, answer)
        self.assertIn("Run the line again", answer["error"])
        status, answer = self.join(code, source=OTHER)                  # it answered, without this address
        self.assertEqual(status, 409, answer)
        self.tailnet[OTHER] = "worker-5"
        status, answer = self.join(code, source=OTHER)                  # the code stayed valid
        self.assertEqual(status, 200, answer)
        with patch.object(hub, "tailnet_status", lambda: None):        # the line again: a repeat needs no read
            self.assertEqual(self.join(code, source=OTHER)[1]["replayed"], True)
        team = self.origin_team()                                       # the server left the fleet since
        del team["addresses"]["worker-5"], team["servers"]["worker-5"]
        with patch.object(hub, "TEAM", team):
            self.assertEqual(self.join(code, source=OTHER)[0], 410)
        status, answer = self.request("/join", {"code": "x", "key_sha256": "0" * 64, "kind": "mac", "user": "dana",
                                                "ssh_port": None}, source=OTHER)
        self.assertEqual(status, 403)


class Columns(Names):
    def test_every_column_of_a_machines_name_is_moved_by_a_rename(self):
        """A new column named machine or server lands here: in MACHINE_COLUMNS, or in a set of columns of that name
        that hold something else, which this test then names."""
        hub.migrate()
        found = set()
        for (table,) in hub.DB.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            for column in hub.DB.execute(f"PRAGMA table_info({table})").fetchall():
                if column["name"] in ("machine", "server"):
                    found.add((table, column["name"]))
        self.assertEqual(found, set(hub.MACHINE_COLUMNS))


class Restore(unittest.TestCase):
    def test_a_copy_stands_its_hub_machine_on_this_one_whatever_each_is_called(self):
        saved = {"hub": {"machine": "worker-2", "port": 8765},
                 "addresses": {"owner": "127.0.0.1", "worker-2": "127.0.0.2", "worker-1": "127.0.0.3",
                               "old-name": "127.0.0.9"},
                 "access": {"worker-2": {"ssh_user": "fleet", "ssh_port": 22}},
                 "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "worker-2", "can": []},
                            "leo": {"role": "worker", "runtime": "claude", "machine": "worker-1", "can": []}}}
        here = {"hub": {"machine": "worker-5", "port": 8765},
                "addresses": {"owner": "127.0.0.1", "worker-5": "127.0.0.9"},
                "agents": {"manager": {"role": "manager", "runtime": "claude", "machine": "worker-5", "can": []}}}
        with patch.object(hub, "TEAM", here):
            team = json.loads(hub.restored_team({"config": {"team.json": json.dumps(saved)}}))
        self.assertEqual(team["hub"], here["hub"])
        self.assertEqual(team["agents"]["manager"]["machine"], "worker-5")
        self.assertEqual(team["addresses"], {"owner": "127.0.0.1", "worker-5": "127.0.0.9", "worker-1": "127.0.0.3"})
        self.assertEqual(team["access"], {"worker-5": {"ssh_user": "fleet", "ssh_port": 22}})


class Adopt(ServerService):
    def tearDown(self):
        hub.MACHINE_NAMES.update(names={}, waits={}, seen=None, asked=0.0, origin_at=0.0)
        super().tearDown()

    def test_the_service_takes_its_new_name_once_its_checkout_has_it(self):
        self.join_by_script(self.code()["code"])
        svc = self.service()
        self.tailnet[NEW] = "danas-mini"
        with hub.LOCK:
            hub.MACHINE_NAMES["names"] = hub.tailnet_machines(tailnet_status(self.tailnet))
            hub.follow_tailnet_names(tailnet_status(self.tailnet), hub.now())
        self.assertIn("danas-mini", self.origin_team()["addresses"])
        self.assertEqual(svc.report(), 200)                             # its checkout has the old team.json still
        self.assertEqual(svc.name, "mini")
        self.assertEqual(json.loads((self.home / ".fleet" / "server.json").read_text())["name"], "mini")
        git("pull", "-q", "--ff-only", cwd=self.own)
        self.assertEqual(svc.report(), 200)
        self.assertEqual(svc.name, "danas-mini")
        self.assertEqual(json.loads((self.home / ".fleet" / "server.json").read_text())["name"], "danas-mini")
        self.assertEqual(svc.report(), 200)                             # and calls with it from now on
        self.assertEqual(svc.hub.call("GET", "/server/danas-mini/jobs")[0], 200)


if __name__ == "__main__":
    unittest.main()

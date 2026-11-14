"""One server for all (owner feature hub_shared): the hub's own server takes agents when the owner chose that at the
install (the first step of the slider "Your fleet's servers", 14 November 2026). The installer writes the word into the
first team.json and gives that server a server service, whose key it puts into the hub's records. Then the owner adds
an agent there as on a joined server: by an install job of that service. An agent that holds servers through the door
still runs alone, and the refusal has a code that the app can read. A hub without the word behaves as before. A local
hub with a temporary Fleet repository; no AI, no machine, no systemd: what a real server must still prove is in
UI-API.md, version 1.168."""
import hashlib
import json
import unittest
from unittest.mock import patch

import hub
import hubsetup
import server
from test_servers import HUB, NEW, OWNER, Servers, sha

REPO = "git://127.0.0.2/fleet-pilot.git"        # the address that the hub's git service gives its machines
LINUX = "Ubuntu 24.04.1 LTS"


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(cls(name) for cls in (NotShared, Shared) for name in cls.__dict__
                              if name.startswith("test_"))


class HubService:
    """The server service of the hub's own server, as hub.sh's step makes it (hubsetup.py hub-server), with no
    systemd: the service's files go to a folder of the test, and the start of the service is only counted."""

    def hub_service(self, team=None, repo=REPO, **more):
        """Run hub-server through the program's own argument list, always with the service's files in a folder of
        the test and with no real service. Returns the service's key, or None when none was made."""
        folder = self.root / "service-home" / ".fleet"
        self.started, self.said = getattr(self, "started", []), getattr(self, "said", [])
        argv = ["hub-server", "--team", str(team or self.kit / "team.json"), "--db", self.path, "--repo", repo]
        with patch.multiple(server, FLEET=str(folder), KEY_FILE=str(folder / "server.key"),
                            CONF_FILE=str(folder / "server.json"), **more.pop("server", {})), \
                patch.object(server, "install_service", lambda: self.started.append(True)), \
                patch.multiple(hubsetup, KEY_TRIES=2, KEY_WAIT=0, say=self.said.append), \
                patch("builtins.print", lambda *a, **k: self.said.append(" ".join(map(str, a)))):
            self.ended = hubsetup.main(argv)
        key = folder / "server.key"
        self.conf = json.loads((folder / "server.json").read_text()) if (folder / "server.json").exists() else None
        return key.read_text().strip() if key.exists() else None

    def manager_has_its_key(self, agent="manager"):
        """The agent's own helper registered its agent key, which a helper alone on its server does at its start."""
        hub.ins("INSERT INTO agent_keys(agent,sha256,created,source) VALUES(?,?,?,'helper')",
                (agent, sha(agent), hub.now()))


class NotShared(HubService, Servers):
    """A hub whose installer got no word: the fleet of every install until 14 November 2026."""

    def test_a_hub_without_the_word_takes_no_agent_as_before(self):
        team = self.fresh_fleet()
        self.assertNotIn("shared", team["hub"])
        self.assertNotIn("servers", team)
        self.assertIs(hub.hub_shared(), False)
        # also with a server service on its own server, and that service's reading: the reason is the hub's
        hub.q("INSERT INTO server_keys(server,sha256,created) VALUES('hub',?,0)", (sha("a-key"),))
        self.assertEqual(self.reading("hub", key="a-key", source=HUB, os_name=LINUX, features=[hub.INSTALL_KEY])[0], 200)
        self.manager_has_its_key()
        view, servers = self.servers()
        self.assertIs(view["hub_shared"], False)
        self.assertEqual((servers["hub"]["available"], servers["hub"]["why"]), (False, ["hub_machine"]))
        self.joined("spare", "linux", source=NEW, user="fleet")
        team = self.origin_team()
        team["agents"]["scout"] = {"role": "worker", "runtime": "codex", "machine": "spare", "can": ["shell"]}
        self.write_team(team)
        status, answer = self.owner("/ui/team/agents/scout/move", base_sha256=self.team_sha(), server="hub")
        self.assertEqual((status, answer["error"]), (409, "No agent runs on the hub's server."))

    def test_the_installer_gives_such_a_hub_no_server_service(self):
        self.fresh_fleet()
        self.manager_has_its_key()
        self.assertIsNone(self.hub_service())
        self.assertEqual((self.ended, self.started, self.conf), (1, [], None))
        self.assertIn("takes no agent", " ".join(self.said))
        self.assertIsNone(hub.q1("SELECT 1 FROM server_keys WHERE server='hub'"))

    def test_the_word_is_true_or_absent_and_the_door_then_has_a_server_of_its_own(self):
        team = hubsetup.template(HUB, owner=OWNER)
        for bad in (False, "yes", 1, None):
            wrong = json.loads(json.dumps(team))
            wrong["hub"]["shared"] = bad
            with self.assertRaises(ValueError, msg=repr(bad)) as refused:
                hub.validate_team(wrong)
            self.assertIn("hub.shared is true for a hub whose own server takes agents, or absent",
                          str(refused.exception))
        self.assertIn("hub_shared", hub.UI_FEATURES)
        # The hub knows the door's own calls by the door's address alone. On a hub's server that takes agents, each
        # agent calls from that address, so the door is refused there. A hub without the word keeps the door there.
        team["door"] = {"address": HUB}
        hub.validate_team(team)
        team["hub"]["shared"] = True
        with self.assertRaises(ValueError) as refused:
            hub.validate_team(team)
        self.assertIn("the door runs on a server of its own in a fleet whose hub's server takes agents",
                      str(refused.exception))
        team["addresses"]["door"] = "127.0.0.77"
        team["door"] = {"address": "127.0.0.77"}        # a server of its own, which no agent runs on
        del team["addresses"]["door"]
        hub.validate_team(team)
        self.assertIs(hub.hub_shared(team), True)

    def test_a_refusal_with_a_code_is_no_conflict(self):
        """A caller that catches Conflict takes it for a team.json that moved, and tries again with no count
        (mac_setup_add). The door's refusal is true at each try, so it stays a plain refusal, with its code beside."""
        refusal = hub.refusal_why("The words of before.", ["door_caller"], agents=["scout"])
        self.assertNotIsInstance(refusal, hub.Conflict)
        self.assertEqual((refusal.status, str(refusal), refusal.extra),
                         (409, "The words of before.", {"why": ["door_caller"], "agents": ["scout"]}))


class Shared(HubService, Servers):
    """The fleet of a customer's first day when the owner chose one server for all: hub.sh with FLEET_HUB_SERVER=shared.
    The manager runs on the hub's server, and that server has its server service."""

    def setUp(self):
        super().setUp()
        self.started, self.said = [], []
        self.team = self.fresh_fleet(shared=True)
        self.manager_has_its_key()
        self.key = self.hub_service()

    def hub_reads(self, features=(hub.INSTALL_KEY,)):
        status, answer = self.reading("hub", key=self.key, source=HUB, os_name=LINUX, features=list(features))
        self.assertEqual(status, 200, answer)

    def test_the_installer_puts_the_owners_choice_on_record(self):
        team = self.origin_team()
        self.assertEqual(team["hub"], {"machine": "hub", "port": 8765, "shared": True})
        self.assertEqual(team["servers"], {"hub": {"kind": "linux", "user": "fleet"}})
        self.assertEqual(team["agents"]["manager"]["machine"], "hub")
        self.assertNotIn("placed", team["agents"]["manager"])
        self.assertIs(hub.hub_shared(), True)
        status, state = self.request(source=OWNER)
        self.assertIn("hub_shared", state["ui_features"])
        self.assertIs(self.servers()[0]["hub_shared"], True)
        # a manager with no server yet and a shared hub server are two layouts: the installer makes one of them
        with self.assertRaises(hubsetup.Stop) as refused:
            hubsetup.template(HUB, owner=OWNER, shared=True, placed=False)
        self.assertIn("one server for all", str(refused.exception))

    def test_the_hubs_server_has_a_server_service_that_the_hub_knows_by_its_key(self):
        """The hub's own address cannot join with a code (join_server refuses it), so the installer writes the key's
        SHA-256 itself, as the hub's own user. The service then calls as each server's service does."""
        self.assertEqual((self.ended, self.started), (0, [True]))
        row = hub.q1("SELECT sha256, created FROM server_keys WHERE server='hub'")
        self.assertEqual(row["sha256"], hashlib.sha256(self.key.encode()).hexdigest())
        self.assertEqual(self.conf, {"name": "hub", "hub": f"http://{HUB}:8765", "repo": REPO})
        # before the service's first reading: the codes of every server in that state, and no word of hub_machine
        self.assertEqual(self.servers()[1]["hub"]["why"], ["has_agent", "no_reading"])
        self.hub_reads()
        hub_ = self.servers()[1]["hub"]
        self.assertEqual((hub_["joined"], hub_["hub"], hub_["agents"], hub_["available"], hub_["why"]),
                         (True, True, ["manager"], True, []))
        status, answer = self.reading("hub", key="another-key", source=HUB, os_name=LINUX)
        self.assertEqual(status, 403, answer)
        status, answer = self.reading("hub", key=self.key, source=NEW, os_name=LINUX)      # the key from another address
        self.assertEqual(status, 403, answer)
        status, answer = self.request("/join", {"code": "ABCD-EFGH-JKLM", "key_sha256": sha("k"), "kind": "linux",
                                                "user": "fleet", "ssh_port": None}, source=HUB)
        self.assertEqual((status, answer["error"]), (403, "This address is the hub. It cannot join as a server."))
        # a second run of the step keeps the key and writes no record again
        self.assertEqual(self.hub_service(), self.key)
        again = hub.q1("SELECT sha256, created FROM server_keys WHERE server='hub'")
        self.assertEqual((again["sha256"], again["created"], self.started), (row["sha256"], row["created"], [True, True]))
        self.assertIn("the hub knows the server service of hub by its key already", self.said)

    def test_the_step_runs_from_the_services_own_clone_with_the_fleets_repository_address(self):
        """The service brings its own checkout up to date by itself, and the hub's checkout is the hub's to move: the
        command refuses to make the service from the hub's checkout. It takes only a git:// address for the agents'
        checkouts."""
        before = hub.q1("SELECT sha256 FROM server_keys WHERE server='hub'")["sha256"]
        self.started.clear()
        self.hub_service(server={"KIT": str(self.kit)})
        self.assertEqual((self.ended, self.started), (1, []))
        self.assertIn("run hub-server from the server service's own clone, not from the hub's checkout",
                      " ".join(self.said))
        self.said.clear()
        self.hub_service(repo="/home/fleet/fleet-pilot.git")
        self.assertEqual((self.ended, self.started), (1, []))
        self.assertIn("--repo must be the git:// address", " ".join(self.said))
        self.assertEqual(hub.q1("SELECT sha256 FROM server_keys WHERE server='hub'")["sha256"], before)

    def test_the_service_waits_for_the_managers_own_key(self):
        """hub.sh installs the manager with no key step: its helper registers its own key while it is alone. From
        the moment the server's service reports that it gives new agents their keys, the hub takes no such key any
        more. So the step starts the service only when the manager's key is in the hub's records, and else stops
        with the reason, with no key made and nothing written."""
        hub.q("DELETE FROM agent_keys")
        hub.q("DELETE FROM server_keys")
        self.started.clear()
        self.said.clear()
        folder = self.root / "service-home" / ".fleet"
        for name in ("server.key", "server.json"):
            (folder / name).unlink()
        self.assertIsNone(self.hub_service())
        self.assertEqual((self.ended, self.started, self.conf), (1, [], None))
        said = " ".join(self.said)
        self.assertIn("manager has no agent key in the hub's records yet", said)
        self.assertIn("so the server service of hub does not start yet", said)
        self.assertIsNone(hub.q1("SELECT 1 FROM server_keys WHERE server='hub'"))
        self.manager_has_its_key()
        self.assertIsNotNone(self.hub_service())
        self.assertEqual((self.ended, self.started), (0, [True]))
        # A second run on a server whose service the hub knows does not wait for a key: an agent that was added
        # there gets its key from that service's install job, and a job that failed leaves the agent with none.
        team = self.origin_team()
        team["agents"]["scout"] = {"role": "worker", "runtime": "codex", "machine": "hub", "can": ["shell"]}
        self.write_team(team)
        self.assertIsNotNone(self.hub_service())
        self.assertEqual((self.ended, self.started), (0, [True, True]))

    def test_the_owner_adds_an_agent_on_the_hubs_server_as_a_job_of_its_own_service(self):
        self.hub_reads()
        self.assertIs(self.servers()[1]["hub"]["available"], True)       # what the app reads before it offers it
        # a name that the hub's own user uses on this server is refused here: the server service runs as that user
        status, refused = self.add_agent(server="hub", agent="git", runtime="codex")
        self.assertEqual((status, refused["error"]),
                         (409, "The hub uses the name git itself on its own server. Choose another name."))
        self.assertEqual(hub.HUB_OWN_NAMES, ("channels", "git", "pilot", "server"))
        self.assertEqual(set(hub.HUB_OWN_NAMES) - set(hubsetup.FLEET_OWN_NAMES), set())
        # the same rule for each other write that could put such a name there: a rename, a move, a reload
        team = self.origin_team()
        team["agents"]["git"] = {"role": "worker", "runtime": "codex", "machine": "hub", "can": ["shell"]}
        with self.assertRaises(ValueError) as refused:
            hub.validate_team(team)
        self.assertIn("agent git: the hub uses the name git itself on its own server, which takes agents",
                      str(refused.exception))
        team["addresses"]["spare"] = NEW
        team["agents"]["git"]["machine"] = "spare"      # on another server the name is the agent's own business
        hub.validate_team(team)
        del team["hub"]["shared"]
        team["agents"]["git"]["machine"] = "hub"        # and a hub without the word has no such rule, as before
        hub.validate_team(team)
        status, receipt = self.add_agent(server="hub", agent="scout", runtime="codex")
        self.assertEqual(status, 200, receipt)
        team = self.origin_team()
        self.assertEqual({n: a["machine"] for n, a in team["agents"].items()}, {"manager": "hub", "scout": "hub"})
        self.assertEqual((team["agents"]["scout"]["active"], team["agents"]["scout"]["vault"]), (False, "none"))
        # its install is a job of the hub's own server service, which calls from the hub's address with its key
        self.assertEqual(self.service("/server/hub/jobs", key=self.key, source=HUB)[1]["jobs"],
                         [{"id": receipt["job"], "kind": "install", "agent": "scout", "runtime": "codex",
                           "state": "queued"}])
        # the installer's own names for the two agents of this server: one OS user for each
        self.assertEqual(hubsetup.agents_of(team, "hub"), ["manager", "scout"])
        self.assertEqual([hubsetup.agent_user(n, team["agents"][n]) for n in ("manager", "scout")],
                         ["fleet-manager", "fleet-scout"])
        status, answer = self.service(f"/server/hub/jobs/{receipt['job']}", {"state": "running", "step": "user",
                                                                           "detail": "Preparing its account."},
                                      key=self.key, source=HUB)
        self.assertEqual(status, 200, answer)
        hub_ = self.servers()[1]["hub"]
        self.assertEqual((hub_["agents"], hub_["why"]), (["manager", "scout"], ["busy"]))
        # each agent of a shared server proves itself with its own key: the manager's helper has one, the new agent's
        # comes with its install job, and until then the two cannot share
        self.assertEqual(hub.placement_missing(["manager", "scout"], team), ["agent_without_key:scout"])

    def test_an_agent_that_holds_servers_through_the_door_runs_alone_and_the_refusal_has_its_code(self):
        """The door knows a caller by its server's address. So the server of an agent that holds servers through the
        door takes no second agent, the hub's own server too, and an agent beside another gets no server through the
        door. Both refusals carry `why`, the code that the app reads."""
        self.hub_reads()
        team = self.origin_team()
        team["agents"]["manager"]["servers"] = {"app-1": "read"}        # the manager holds a server for apps
        self.write_team(team)
        hub_ = self.servers()[1]["hub"]
        self.assertEqual((hub_["available"], hub_["why"]), (False, ["door_caller"]))
        status, refused = self.add_agent(server="hub", agent="scout", runtime="codex")
        self.assertEqual(status, 409, refused)
        self.assertEqual(refused["why"], ["door_caller"])
        self.assertEqual(refused["error"], "Manager holds servers through the door and runs alone on hub, by which the "
                                           "door knows it: a new agent goes to another server.")
        self.assertEqual(list(self.origin_team()["agents"]), ["manager"])
        # the other side: two agents share the hub's server, and neither gets a server through the door
        del team["agents"]["manager"]["servers"]
        self.write_team(team)
        status, receipt = self.add_agent(server="hub", agent="scout", runtime="codex")
        self.assertEqual(status, 200, receipt)
        status, refused = self.owner("/ui/servers/grant", agent="scout", server="app-1", level="read")
        self.assertEqual(status, 409, refused)
        self.assertEqual((refused["why"], refused["agents"]), (["shares_server"], ["manager"]))
        self.assertIn("an agent that holds servers through the door runs alone on its server", refused["error"])
        self.assertNotIn("servers", self.origin_team()["agents"]["scout"])

    def test_a_move_goes_to_an_empty_server_so_the_hubs_server_with_its_manager_takes_none(self):
        self.hub_reads()
        self.joined("spare", "linux", source=NEW, user="fleet")
        team = self.origin_team()
        team["agents"]["scout"] = {"role": "worker", "runtime": "codex", "machine": "spare", "can": ["shell"]}
        self.write_team(team)
        status, answer = self.owner("/ui/team/agents/scout/move", base_sha256=self.team_sha(), server="hub")
        self.assertEqual((status, answer["error"]), (409, "hub has an agent already: manager"))


if __name__ == "__main__":
    unittest.main()

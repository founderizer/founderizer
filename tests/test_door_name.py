"""A server named `door` (the owner's "Yes, fix it" of 16 November 2026, C49). The central vault keeps the door's pin
and the seals of its grants under that name (`hub.DOOR_PIN`), and each server's pin and grants by the server's name,
so a server with that name would take the door's pin. The join refuses the name with its code, a rename in Tailscale
to it waits for ever, and a fleet that has such a server from before starts, gives its vault nothing from the central
vault, and tells the fleet manager once. Against a local hub, as test_machine_names."""
import copy
import unittest
from unittest.mock import patch

import hub
import refusal_words
from test_machine_names import Names
from test_servers import NEW, OTHER, tailnet_status


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(DoorName(name) for name in DoorName.__dict__ if name.startswith("test_"))


class DoorName(Names):
    def test_the_name_is_the_doors_own_in_the_central_vault(self):
        self.assertEqual(hub.DOOR_PIN, "door")
        self.assertEqual(refusal_words.WORDS["server_name_kept"], "This server is called {name} in Tailscale, and "
                         "Fleet keeps that name for itself. Rename this server in Tailscale, then run the line again.")

    def test_a_join_refuses_the_doors_name_with_its_code(self):
        self.tailnet[OTHER] = "door"
        status, answer = self.join(self.code("door", "linux")["code"], source=OTHER, kind="linux", user="fleet")
        self.assertEqual(status, 409, answer)
        self.assertEqual((answer.get("code"), answer.get("names")), ("server_name_kept", {"name": "door"}))
        self.assertEqual(answer["error"], "This server is called door in Tailscale, and Fleet keeps that name for "
                                          "itself. Rename this server in Tailscale, then run the line again.")
        self.assertNotIn("door", self.origin_team()["addresses"])
        self.tailnet[OTHER] = "owner"                                   # the name of before: its refusal as it was
        status, answer = self.join(self.code("owner", "linux")["code"], source=OTHER, kind="linux", user="fleet")
        self.assertEqual(status, 409)
        self.assertIn("a server's name in Fleet has 2 to 31 characters", answer["error"])

    def test_a_rename_to_the_doors_name_waits_and_says_why_once(self):
        self.tailnet[NEW] = "door"
        self.read_twice()
        self.read_twice()
        self.assertIn("mini", self.origin_team()["addresses"])
        self.assertNotIn("door", self.origin_team()["addresses"])
        hub.MACHINE_NAMES.update(waits={}, names={})                    # a restart forgets what it read
        self.read_twice()
        told = [t for t in self.said() if "is called door in Tailscale" in t]
        self.assertEqual(len(told), 1, told)                            # a lasting reason, told once, a restart too
        self.assertIn("door is the name under which the central vault keeps the door's pin and grants", told[0])
        self.assertTrue(hub.tailnet_rename_wait("mini", "door", hub.now())[1])

    def test_a_fleet_with_such_a_server_from_before_starts_and_its_vault_gets_nothing(self):
        team = copy.deepcopy(self.origin_team())
        team["addresses"]["door"] = "100.80.1.9"
        team.setdefault("servers", {})["door"] = {"kind": "linux", "user": "fleet"}
        hub.validate_team(team)                                         # an older team.json still loads
        agents = {"scout": {"role": "worker", "machine": "door", "vault": "broker"}}
        found = hub.deposit_machines({"agents": agents})
        self.assertEqual(found["door"], {"machine": "door", "agents": ["scout"], "carrier": None, "recipient": None,
                                         "missing": ["machine_name_kept"]})
        # the fleet manager hears once, across sweeps and restarts, what the owner must do
        with patch.dict(hub.TEAM["addresses"], {"door": "100.80.1.9"}):
            for _ in range(3):
                with hub.LOCK:
                    hub.follow_tailnet_names(tailnet_status(self.tailnet), hub.now())
                hub.MACHINE_NAMES.update(waits={}, names={})
        told = [t for t in self.said() if t.startswith("[hub] The server door has the name")]
        self.assertEqual(len(told), 1, self.said())
        self.assertIn("It must leave Fleet and join again under another name", told[0])


if __name__ == "__main__":
    unittest.main()

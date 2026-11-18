"""Sealed handovers are used for one task, then thrown away. In-process hub; no age, vault or AI calls."""
import unittest
from unittest.mock import patch

import fleet
import hub
from test_ui_api import OwnerAPI

ARMORED = "-----BEGIN AGE ENCRYPTED FILE-----\nlocked\n-----END AGE ENCRYPTED FILE-----\n"


def load_tests(loader, _tests, _pattern):
    suite = unittest.TestSuite(Handover(name) for name in Handover.__dict__ if name.startswith("test_"))
    suite.addTests(loader.loadTestsFromTestCase(HelperFetch))
    return suite


class Handover(OwnerAPI):
    def setUp(self):
        super().setUp()
        hub.TEAM["agents"]["studio"] = dict(role="worker", runtime="claude", machine="studio", can=["browser"])
        hub.TEAM["addresses"]["studio"] = "127.0.0.1"

    def sealed(self, created=None):
        return hub.ins("INSERT INTO sealed(sender,recipient,task,label,ciphertext,created) VALUES(?,?,?,?,?,?)",
                       ("vps", "studio", "T-1", "practice", ARMORED, created or hub.now()))

    def task(self, state="working"):
        return hub.ins("INSERT INTO tasks(title,owner,requester,state,created) VALUES('Sign in','studio','manager',?,?)",
                       (state, hub.now()))

    def fetch(self, sid, task):
        return self.request(f"/sealed/{sid}?agent=studio&task=T-{task}")

    def test_the_first_task_owns_the_handover_until_it_ends(self):
        sid, mine, other = self.sealed(), self.task(), self.task()
        code, data = self.fetch(sid, mine)
        self.assertEqual((code, data["ciphertext"]), (200, ARMORED))
        self.assertEqual(self.fetch(sid, mine)[0], 200)                     # sign-in retries in the same task
        self.assertEqual(self.fetch(sid, other)[0], 403)
        hub.expire_handovers(hub.now())
        self.assertEqual(self.fetch(sid, mine)[0], 200)                     # the task is still open
        hub.q("UPDATE tasks SET state='completed' WHERE id=?", (mine,))
        hub.expire_handovers(hub.now())
        self.assertEqual(self.fetch(sid, mine)[0], 410)
        self.assertIsNone(hub.q1("SELECT ciphertext FROM sealed WHERE id=?", (sid,))["ciphertext"])

    def test_a_handover_opened_without_a_task_is_refused_and_binds_nothing(self):
        """The whole rule is that the first task to open a handover owns it, and the binding to that task is what
        holds it. A request that named no task was answered with the locked copy and bound nothing, so the
        recipient could open the same login from every later task of that day by leaving `task` out, and nothing
        would ever throw the copy away: `expire_handovers` waits for the end of the bound task, and an unbound copy
        only for the day to pass. The recipient has its own agent key on its own machine, so this is a request it
        can make."""
        sid, mine = self.sealed(), self.task()
        for query in (f"/sealed/{sid}?agent=studio", f"/sealed/{sid}?agent=studio&task=", f"/sealed/{sid}?agent=studio&task=T-0"):
            code, data = self.request(query)
            self.assertEqual(code, 400, data)
            self.assertIn("name the task", data["error"])
        self.assertIsNone(hub.q1("SELECT bound_task FROM sealed WHERE id=?", (sid,))["bound_task"])
        self.assertEqual(self.fetch(sid, mine)[0], 200)              # it is this task's now
        self.assertEqual(self.request(f"/sealed/{sid}?agent=studio")[0], 400)       # and no way round that

    def test_an_unopened_handover_is_thrown_away_after_a_day(self):
        old, fresh = self.sealed(created=hub.now() - 2 * 86400), self.sealed()
        hub.expire_handovers(hub.now())
        self.assertEqual(self.fetch(old, self.task())[0], 410)
        self.assertEqual(self.fetch(fresh, self.task())[0], 200)


class HelperFetch(unittest.TestCase):
    def setUp(self):        # the file-mode fetch; in broker mode only the vault broker opens a handover
        p = patch.object(fleet, "vault_mode", return_value="file")
        p.start()
        self.addCleanup(p.stop)

    def test_the_helper_names_the_task_that_opens_a_handover(self):
        with patch("fleet.http", return_value=(410, {"error": "S-3 has expired"})) as http:
            with self.assertRaises(fleet.Refused) as refused:
                fleet.read_login("sealed:3", "studio", "T-9")
        self.assertIn("task=T-9", http.call_args.args[1])
        self.assertIn("expired", str(refused.exception))


if __name__ == "__main__":
    unittest.main()

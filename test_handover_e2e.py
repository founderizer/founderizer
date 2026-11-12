"""A login from one agent to another, end to end. A lead's own wake-up rule starts its task from the hub tick; in
that session it gives one worker the handover and another the use. The hub's own tools, tick and routes, the helper's
own event handling and the real Linux broker on a socket. The store and age are the stand-ins of test_vault. The
receiver signs in, which is the Mac vault helper's work and not in this repository: a stand-in does it with the
broker's own steps. No AI session, no other host, no account, no real token and no real key."""
import concurrent.futures
import json
import threading
import time
import unittest
from unittest.mock import patch

import fleet
import hub
import vault
from test_capacity import Capacity
from test_vault import AGENT_KEY, LOGIN, REF, VaultBroker

WAKE = {"title": "Check the login", "details": "", "done_when": "A worker used the handed-over login.",
        "needs": "none", "goal_id": None}


def load_tests(loader, _tests, _pattern):
    return unittest.TestSuite(Handover(name) for name in Handover.__dict__ if name.startswith("test_"))


class Handover(VaultBroker):
    """worker4 leads vps and studio, each on a machine with its own vault broker and handover key. mini has a broker
    too, but may use no login of this flow."""
    call, create, refused = Capacity.call, Capacity.create, Capacity.refused      # the tool calls of a task session

    def setUp(self):
        super().setUp()
        hub.TEAM["agents"].update(
            worker4=dict(role="lead", runtime="codex", machine="worker4", can=["shell"]),
            mini=dict(role="worker", runtime="codex", machine="mini", can=["shell"], vault="none"))
        hub.TEAM["agents"]["vps"]["reports_to"] = hub.TEAM["agents"]["studio"]["reports_to"] = "worker4"
        hub.TEAM["addresses"].update(worker4="127.0.0.6", mini="127.0.0.7")
        hub.q("UPDATE tasks SET state='canceled' WHERE id=?", (self.task,))       # the fixture's task is not in this flow
        self.keys["studio"].chmod(0o600)
        studio = dict(self.conf, agent="studio", age_key=str(self.keys["studio"]), socket=str(self.dir / "studio.sock"))
        broker = vault.Broker(studio).open()
        threading.Thread(target=broker.serve, daemon=True).start()
        self.addCleanup(broker.close)
        self.sockets = {"vps": self.conf["socket"], "studio": studio["socket"]}
        self.ahead, self.signed_in, real = 0.0, [], vault.handle

        def handle(conf, line, uid):
            """A broker that also signs in: the stand-in for the Mac vault helper. It does a sign-in job with the Linux
            broker's own steps before a use (the hub's confirmation, the copy opened with this machine's key and
            checked, the protection) and fills no form."""
            request = json.loads(line)
            if request.get("op") != "signin":
                return real(conf, line, uid)
            confirmed = vault.confirm_job(conf, request["job"], "signin")
            login, label, _ = vault.open_login(conf, confirmed["login"], confirmed["task"], "unused")
            vault.protect(conf, confirmed, login)
            self.signed_in.append(login)
            return {"ok": True, "v": vault.PROTOCOL, "job": request["job"], "origin": vault.origin(login["url"])[2],
                    "label": label}

        for p in (patch.dict(hub.CFG, dict(silence=180, question_wait=120, manager_silence=120, stop_after=60,
                                           offline_after=90, job_wait=20)),
                  patch.object(hub, "now", lambda: time.time() + self.ahead),      # the real clock, moved to a due time
                  patch.object(vault, "handle", handle),
                  patch.object(fleet, "tmux", side_effect=AssertionError("this test starts no session"))):
            p.start()
            self.addCleanup(p.stop)

    # ---- helpers
    def session(self, agent, task):
        """The start of a task session, as the hub's start text asks: the messages are read and the task is listed."""
        for name in ("read_messages", "list_my_tasks"):
            text, error = self.call(agent, name, {}, task)
            self.assertFalse(error, text)
        return task

    def deliver(self, agent, task, what):
        text, error = self.call(agent, "deliver_result", {"what_was_done": what, "where_output_is": "The hub's records.",
                                                         "how_checked": "Read there."}, task)
        self.assertFalse(error, text)

    def tick(self, at=None):
        """The hub's own tick, now or at a later time. Each helper checked in a moment before."""
        if at is not None:
            self.ahead += at - hub.now()
        for name in hub.TEAM["agents"]:
            hub.touch(name)
        hub.tick()

    def with_machine(self, agent, name, args, task):
        """A tool call that waits for the agent's machine, and the tool's answer. The machine's helper asks the hub for
        its work as the loop of fleet.py does, and gives the one login job to fleet.Helper.handle; the machine's
        broker does the rest."""
        helper = fleet.Helper.__new__(fleet.Helper)         # no session and no tailer: this helper does jobs only
        helper.agent, helper.outside, helper.outside_lock, helper.say = agent, 0, threading.Lock(), lambda text: None
        helper.jobs_held, helper.report_waits = {}, {}      # plan C7: the jobs it holds, and their reports
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            answer = pool.submit(self.call, agent, name, args, task)
            deadline = time.monotonic() + 20
            while True:
                events = self.request(f"/events/{agent}?delivery=1&after=0&wait=1")[1]["events"]
                jobs = [e for e in events if e["kind"] in ("signin", "handover")]
                if jobs or answer.done() or time.monotonic() > deadline:
                    break
                time.sleep(0.05)
            self.assertEqual(len(jobs), 1, events)
            with patch.object(fleet, "vault_socket", return_value=self.sockets[agent]):
                helper.handle(jobs[0])
            return answer.result(30)

    # ---- the flow
    def test_a_woken_lead_has_a_login_handed_over_between_its_workers_and_used_for_one_task(self):
        # The fleet manager gives the lead its task. There it sets its own rule, and the task ends.
        first = self.session("worker4", self.create("manager", "worker4", why="worker4 leads both."))
        text, error = self.call("worker4", "save_trigger", {"request_id": "worker4-wake-0001",
                                                            "schedule": {"kind": "every", "minutes": 5}, "task": WAKE}, first)
        self.assertFalse(error, text)
        rule = hub.q1("SELECT * FROM triggers")
        self.assertEqual((rule["agent"], rule["created_by"]), ("worker4", "worker4"))
        self.deliver("worker4", first, "My wake-up rule is set.")
        self.call("manager", "read_messages", {})                           # the fleet manager reads that result
        # The hub tick at the rule's time: one task for the lead, from the fleet manager.
        before = hub.q1("SELECT MAX(id) m FROM tasks")["m"]
        self.tick(rule["next_due"])
        (woken,) = hub.q("SELECT * FROM tasks WHERE id>?", (before,))
        run = hub.q1("SELECT * FROM trigger_runs WHERE trigger_id=?", (rule["id"],))
        self.assertEqual((run["state"], run["task"], run["event_id"], run["parent_task"]), ("started", woken["id"], None, None))
        self.assertEqual((woken["owner"], woken["requester"], woken["parent"], woken["trigger_id"]),
                         ("worker4", "manager", None, rule["id"]))
        pm = self.session("worker4", woken["id"])
        # In the woken session it gives the handover to one worker. An agent with no credential access gets none.
        sender = self.session("vps", self.create("worker4", "vps", pm, title="Hand the login over to studio"))
        self.assertIn("mini has no credential access", self.refused("vps", "hand_over", {"login": REF, "to": "mini"}, sender))
        self.assertEqual(self.count("jobs"), 0)                             # nothing went to a machine
        text, error = self.with_machine("vps", "hand_over", {"login": REF, "to": "studio"}, sender)
        self.assertFalse(error, text)
        name, copy = text.split()[0], hub.q1("SELECT * FROM sealed")
        made = hub.q1("SELECT * FROM jobs WHERE agent='vps' AND kind='handover'")
        self.assertEqual((made["task"], made["ok"]), (sender, 1))
        self.assertEqual((name, copy["sender"], copy["recipient"], copy["task"], copy["login"], copy["job"]),
                         (f"sealed:{copy['id']}", "vps", "studio", f"T-{sender}", REF, made["id"]))
        self.assertEqual(self.opens(copy["ciphertext"], "studio"), LOGIN)   # locked for the receiver's pinned key only
        self.assertIsNone(self.opens(copy["ciphertext"], "vps"))
        self.assertIsNone(self.opens(copy["ciphertext"], "agent"))          # another machine's key
        self.assertEqual(self.made(copy["ciphertext"], "studio"), {"v": 1, "job": made["id"], "source": REF})
        self.deliver("vps", sender, f"{name} is for studio.")
        # The receiver uses the copy in its own subtask of that session, after the sender's task ended.
        use = self.session("studio", self.create("worker4", "studio", pm, title="Sign in", details=f"Use {name}."))
        self.assertEqual([tuple(r) for r in hub.q("SELECT parent, requester FROM tasks WHERE id IN (?,?)", (sender, use))],
                         [(pm, "worker4")] * 2)
        self.assertEqual(self.count("jobs"), 1)
        text, error = self.with_machine("studio", "sign_in", {"login": name}, use)
        self.assertFalse(error, text)
        self.assertIn(f"with the login \"{copy['label']}\". The password was never shown to you.", text)
        self.assertEqual(self.signed_in, [LOGIN])
        self.assertEqual(hub.q1("SELECT bound_task FROM sealed WHERE id=?", (copy["id"],))["bound_task"], use)
        # The copy lasted for that one task: after its end, the next tick throws it away.
        self.deliver("studio", use, "Signed in.")
        self.tick()
        gone = hub.q1("SELECT ciphertext IS NULL AS empty, expired FROM sealed WHERE id=?", (copy["id"],))
        self.assertEqual((gone["empty"], bool(gone["expired"])), (1, True))
        again = self.session("studio", self.create("worker4", "studio", pm, title="Sign in again", details=f"Use {name}."))
        text, error = self.with_machine("studio", "sign_in", {"login": name}, again)
        self.assertTrue(error, text)
        self.assertIn("has expired: a handover lasts for one task only", text)
        self.assertEqual(self.signed_in, [LOGIN])                           # opened once
        # Each value was protected before its use, and no record of the hub has one.
        self.assertTrue(hub.secret_hit(LOGIN["password"]))
        self.assertEqual(hub.leak_scan(), [])


if __name__ == "__main__":
    unittest.main()
